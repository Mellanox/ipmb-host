// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2019 Mellanox Technologies
 *
 * Adapted from the bt-i2c driver by Brendan Higgins.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ipmi_smi.h>
#include <linux/i2c.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/types.h>

#define	PFX				"IPMB HOST: "
#define	IPMB_TIMEOUT			(msecs_to_jiffies(5000))

/*
 * The least we exepect in an IPMB message is:
 * netfn_rs_lun, checksum1, rq_sa, rq_seq_rq_lun,
 * cmd and checksum2.
 */
#define	IPMB_LEN_MIN			6

/*
 * Within the response message, we need at least
 * netfn_rq_lun, checksum1, rs_sa, rq_seq_rs_lun,
 * cmd, completion and checksum2.
 */
#define	IPMB_RESPONSE_LEN_MIN		7

#define	IPMB_MSG_PAYLOAD_LEN_MAX	122

#define	IPMB_SMI_MSG_PAYLOAD_LEN_MAX	(IPMI_MAX_MSG_LENGTH - 2)
#define	IPMB_MAX_SMI_SIZE		125
#define	IPMB_SMI_MSG_HEADER_SIZE	2

#define	IPMB_SEQ_MAX			1024

#define	MAX_BUF_SIZE			122

#define	WRITE_TIMEOUT			25
#define	RSP_QUEUE_MAX_LEN		256

#define	NETFN_RSP_BIT			0x4

#define	GET_SEQ(lun_seq)		(lun_seq >> 2)

struct request {
	/*
	 * u8 rs_sa;
	 * rs_sa (rq_sa for rsp) is not part of the msg struct because
	 * it is already integrated within the smbus message format.
	 * the first data byte in the smbus message is the netfunction.
	 */
	u8 netfn_rs_lun;	/* netfn_rq_lun for rsp */
	u8 checksum1;
	u8 rq_sa;		/* rs_sa for rsp */
	u8 rq_seq_rq_lun;	/* rq_seq_rs_lun for rsp */
	u8 cmd;
	u8 payload[IPMB_MSG_PAYLOAD_LEN_MAX];
	/* checksum2 is the last element of the payload */
} __packed;

struct response {
	/*
	 * u8 rq_sa;
	 * It is not part of the msg struct because
	 * it is already integrated within the smbus message format.
	 * the first data byte in the smbus message is the netfunction.
	 */
	u8 netfn_rq_lun;
	u8 checksum1;
	u8 rs_sa;
	u8 rq_seq_rs_lun;
	u8 cmd;
	/* completion code is the first element of the payload */
	u8 payload[IPMB_MSG_PAYLOAD_LEN_MAX];
	/* checksum2 is the last element of the payload */
} __packed;

union ipmb_msg {
	struct request rq;
	struct response rs;
};

/*
 * The ipmb_smi_msg struct is passed by the ipmi_smi_msg struct from
 * in the ipmi_msghandler module. So it needs to have the same structure
 * as ipmi_smi_msg. Refer to the linux code and libraries for
 * more details.
 */
struct ipmb_smi_msg {
	u8 netfn_lun;
	u8 cmd;
	u8 payload[IPMB_SMI_MSG_PAYLOAD_LEN_MAX];
} __packed;

struct ipmb_seq_entry {
	struct ipmi_smi_msg	*msg;
	unsigned long		send_time;
};

struct ipmb_rsp_elem {
	struct list_head	list;
	union ipmb_msg		rsp;
};

struct ipmb_master {
	struct ipmi_device_id		ipmi_id;
	/* Used to register this device as a slave device */
	struct i2c_client		*client;
	ipmi_smi_t			intf;
	spinlock_t			lock;
	struct ipmb_seq_entry		seq_msg_map[IPMB_SEQ_MAX];
	struct work_struct		ipmb_send_work;
	struct ipmi_smi_msg		*msg_to_send;
	/* Responder's I2C slave address */
	u32				rs_sa;

	/* This is all for the response message */
	size_t				msg_idx;
	union ipmb_msg			rsp;
	struct list_head		rsp_queue;
	atomic_t			rsp_queue_len;
	wait_queue_head_t		wait_queue;
};

/*
 * This function gets the actual size of the ipmb message
 * passed by ipmitool program. The last element of the
 * request msg is a checksum. A checksum is always non 0,
 * so we use this property to retrieve the size of the
 * message
 */
static int ipmb_msg_len(u8 *msg)
{
	int i;

	i = MAX_BUF_SIZE - 1;

	if (msg == NULL)
		return -1;

	msg = msg + i;

	while (*msg == 0x0) {
		msg--;
		i--;

		if (i == 0)
			return 0;
	}
	/* i is the index so add 1 for size of msg */
	return i + 1;
}

/*
 * ipmb_handle_response puts the received response message in
 * a queue. The response will eventually be passed on to
 * ipmitool.
 */
static int ipmb_handle_response(struct ipmb_master *master)
{
	struct ipmb_rsp_elem *queue_elem;

	if (atomic_read(&master->rsp_queue_len) >=
			RSP_QUEUE_MAX_LEN)
		return -EFAULT;

	queue_elem = kmalloc(sizeof(*queue_elem), GFP_KERNEL);
	if (!queue_elem)
		return -ENOMEM;
	memcpy(&queue_elem->rsp, &master->rsp,
		sizeof(union ipmb_msg));

	list_add(&queue_elem->list, &master->rsp_queue);
	atomic_inc(&master->rsp_queue_len);
	wake_up_all(&master->wait_queue);
	return 0;
}

/*
 * All this function does is send the request msg via I2C by calling
 * i2c_master_send
 */
static int ipmb_send_request(struct ipmb_master *master,
				union ipmb_msg *request)
{
	struct i2c_client *client = master->client;
	unsigned long timeout, read_time;
	u8 *buf = (u8 *) &request->rq;
	int ret;
	int msg_len;
	union i2c_smbus_data data;

	/*
	 * subtract netfn_rs_lun payload since it is passed as arg
	 * 5 to i2c_smbus_xfer.
	 */
	msg_len = ipmb_msg_len(buf) - 1;
	if (msg_len > I2C_SMBUS_BLOCK_MAX)
		msg_len = I2C_SMBUS_BLOCK_MAX;

	data.block[0] = msg_len;
	memcpy(&data.block[1], buf + 1, msg_len);

	timeout = jiffies + msecs_to_jiffies(WRITE_TIMEOUT);
	do {
		read_time = jiffies;

		ret = i2c_smbus_xfer(client->adapter, (u16)master->rs_sa,
				    client->flags, I2C_SMBUS_WRITE,
				    request->rq.netfn_rs_lun,
				    I2C_SMBUS_BLOCK_DATA, &data);
		if (ret == 0)
			return ret;
		usleep_range(1000, 1500);
	} while (time_before(read_time, timeout));

	return ret;
}

static int ipmb_start_processing(void *data, ipmi_smi_t intf)
{
	struct ipmb_master *master = data;

	master->intf = intf;

	return 0;
}

static u8 ipmb_checksum1(u8 rs_sa, u8 netfn_rs_lun)
{
	u8 csum = rs_sa;

	csum += netfn_rs_lun;
	return -csum;
}

static u8 ipmb_checksum(u8 *data, int size, u8 start)
{
	u8 csum = start;

	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static void __ipmb_error_reply(struct ipmb_master *master,
				struct ipmi_smi_msg *msg,
				u8 completion_code)
{
	struct ipmb_smi_msg *response;
	struct ipmb_smi_msg *request;

	response = (struct ipmb_smi_msg *) msg->rsp;
	request = (struct ipmb_smi_msg *) msg->data;

	response->netfn_lun = request->netfn_lun | NETFN_RSP_BIT;
	response->cmd = request->cmd;
	response->payload[0] = completion_code;
	msg->rsp_size = 3;
	ipmi_smi_msg_received(master->intf, msg);
}

static void ipmb_error_reply(struct ipmb_master *master,
				struct ipmi_smi_msg *msg,
				u8 completion_code)
{
	unsigned long flags;

	spin_lock_irqsave(&master->lock, flags);
	__ipmb_error_reply(master, msg, completion_code);
	spin_unlock_irqrestore(&master->lock, flags);
}

/*
 * ipmb_smi_msg contains a payload and 2 header fields: netfn_lun and cmd.
 * Its payload does not contain checksum2.
 *
 * Each struct in the ipmb_msg union contains a payload
 * (including checksum2) and 5 header fields: netfn_r*_lun, checksum1,
 * r*_sa, rq_seq_r*_lun, cmd. So we need to add one byte for each field
 * which is present in ipmb_msg and not in ipmb_smi_msg: checksum1,
 * r*_sa, rq_seq_r*_lun and checksum2.
 */
static u8 ipmi_smi_to_ipmb_len(size_t smi_msg_size)
{
	return smi_msg_size + 4;
}

/*
 * This function is the converse of the above.
 */
static u8 ipmb_to_smi_len(u8 msg_len)
{
	return msg_len - 4;
}

/*
 * This function gets the length of the payload in
 * ipmb_msg.
 * Subtract one byte for each: netfn_rs_lun, checksum1,
 * rq_sa, rq_seq_rq_lun, cmd and checksum2
 */
static size_t ipmb_payload_len(size_t msg_len)
{
	return msg_len - 6;
}

static bool ipmb_assign_seq(struct ipmb_master *master,
				struct ipmi_smi_msg *msg, u8 *ret_seq)
{
	struct ipmb_seq_entry *entry;
	bool did_cleanup = false;
	unsigned long flags;
	u8 seq;

	spin_lock_irqsave(&master->lock, flags);
retry:
	for (seq = 0; seq < IPMB_SEQ_MAX; seq++) {
		if (!master->seq_msg_map[seq].msg) {
			master->seq_msg_map[seq].msg = msg;
			master->seq_msg_map[seq].send_time = jiffies;
			spin_unlock_irqrestore(&master->lock, flags);
			*ret_seq = seq;
			return true;
		}
	}

	if (did_cleanup) {
		spin_unlock_irqrestore(&master->lock, flags);
		return false;
	}

	/*
	 * TODO: we should do cleanup at times other than only when we run out
	 * of sequence numbers.
	 */
	for (seq = 0; seq < IPMB_SEQ_MAX; seq++) {
		entry = &master->seq_msg_map[seq];
		if (entry->msg &&
			time_after(entry->send_time + IPMB_TIMEOUT,
			jiffies)) {
			__ipmb_error_reply(master, entry->msg,
					IPMI_TIMEOUT_ERR);
			entry->msg = NULL;
		}
	}
	did_cleanup = true;
	goto retry;
}

static struct ipmi_smi_msg *ipmb_find_msg(
		struct ipmb_master *master, u8 seq)
{
	struct ipmi_smi_msg *msg;
	unsigned long flags;

	spin_lock_irqsave(&master->lock, flags);
	msg = master->seq_msg_map[seq].msg;
	spin_unlock_irqrestore(&master->lock, flags);
	return msg;
}

static void ipmb_free_seq(struct ipmb_master *master, u8 seq)
{
	unsigned long flags;

	spin_lock_irqsave(&master->lock, flags);
	master->seq_msg_map[seq].msg = NULL;
	spin_unlock_irqrestore(&master->lock, flags);
}

/*
 * When this function is called, it waits until receiving an
 * IPMI message in the response queue. If a response is found
 * in the queue, it will be copied to ipmb_rsp.
 * If no response is received after a timeout of 1000 ms, then
 * the function returns with an error code. It will return:
 * - 0 if there was no msg in the response queue after the timeout elapsed
 * - A strictly positive number if a msg was found in the queue and
 *   ipmb_rsp was successfully populated.
 * - A negative value for errors.
 */
static int ipmb_receive_rsp(struct ipmb_master *master,
				bool non_blocking,
				union ipmb_msg *ipmb_rsp)
{
	struct ipmb_rsp_elem	*queue_elem;
	int			ret = 0;

	spin_lock_irq(&master->lock);

	while (list_empty(&master->rsp_queue)) {
		spin_unlock_irq(&master->lock);

		if (non_blocking)
			return -EAGAIN;

		ret = wait_event_interruptible_timeout(master->wait_queue,
			!list_empty(&master->rsp_queue), IPMB_TIMEOUT);

		if (ret <= 0)
			return ret;

		spin_lock_irq(&master->lock);
	}

	queue_elem = list_first_entry(&master->rsp_queue,
			struct ipmb_rsp_elem, list);
	memcpy(&ipmb_rsp->rs, &queue_elem->rsp, sizeof(ipmb_rsp->rs));
	list_del(&queue_elem->list);
	kfree(queue_elem);
	atomic_dec(&master->rsp_queue_len);
	spin_unlock_irq(&master->lock);

	return ret;
}

/*
 * This function is called by ipmb_sender.
 * It checks whether the message to be sent has an acceptable size,
 * it assigns a sequence number to the msg
 * it calls ipmb_send_request to send the msg to the receiver
 * via I2C.
 */
static void ipmb_send_workfn(struct work_struct *work)
{
	struct ipmb_master		*master;

	struct ipmb_smi_msg		*smi_msg;
	union ipmb_msg			ipmb_req_msg;
	struct ipmi_smi_msg		*req_msg;

	struct ipmb_smi_msg		*smi_rsp_msg;
	union ipmb_msg			ipmb_rsp_msg;
	struct ipmi_smi_msg		*rsp_msg;

	size_t				smi_msg_size;
	u8				msg_len;
	unsigned long			flags;
	int				rsp_msg_len;
	u8 				*buf_rsp;
	u8 				verify_checksum;

	u8 *buf = (u8 *) &ipmb_req_msg.rq;

	memset(&ipmb_req_msg.rq, 0, sizeof(ipmb_req_msg.rq));

	master = container_of(work, struct ipmb_master,
			     ipmb_send_work);

	req_msg = master->msg_to_send;
	smi_msg_size = req_msg->data_size;
	smi_msg = (struct ipmb_smi_msg *) req_msg->data;

	if (smi_msg_size > IPMB_MAX_SMI_SIZE) {
		ipmb_error_reply(master, req_msg, IPMI_REQ_LEN_EXCEEDED_ERR);
		return;
	}

	if (smi_msg_size < IPMB_SMI_MSG_HEADER_SIZE) {
		ipmb_error_reply(master, req_msg, IPMI_REQ_LEN_INVALID_ERR);
		return;
	}

	if (!ipmb_assign_seq(master, req_msg, &ipmb_req_msg.rq.rq_seq_rq_lun)) {
		ipmb_error_reply(master, req_msg, IPMI_NODE_BUSY_ERR);
		return;
	}

	msg_len = ipmi_smi_to_ipmb_len(smi_msg_size);

	/* Responder  */
	ipmb_req_msg.rq.netfn_rs_lun = smi_msg->netfn_lun;
	ipmb_req_msg.rq.checksum1 = ipmb_checksum1((u8)(master->rs_sa << 1),
						ipmb_req_msg.rq.netfn_rs_lun);

	/* Requester is this device */
	ipmb_req_msg.rq.rq_sa = (u8)(master->client->addr << 1);
	ipmb_req_msg.rq.cmd = smi_msg->cmd;

	memcpy(ipmb_req_msg.rq.payload, smi_msg->payload,
		ipmb_payload_len((size_t)msg_len));
	ipmb_req_msg.rq.payload[ipmb_payload_len((size_t)msg_len)] =
		ipmb_checksum(buf + 2, msg_len - 2, 0);

	if (ipmb_send_request(master, &ipmb_req_msg) < 0) {
		ipmb_free_seq(master, (GET_SEQ(ipmb_req_msg.rq.rq_seq_rq_lun)));
		ipmb_error_reply(master, req_msg, IPMI_BUS_ERR);
		spin_lock_irqsave(&master->lock, flags);
		master->msg_to_send = NULL;
		spin_unlock_irqrestore(&master->lock, flags);
		return;
	}

	spin_lock_irqsave(&master->lock, flags);
	master->msg_to_send = NULL;
	spin_unlock_irqrestore(&master->lock, flags);

	/* Done with sending request. Now handling response */

	if (ipmb_receive_rsp(master, false, &ipmb_rsp_msg) <= 0) {
		ipmb_free_seq(master, (GET_SEQ(ipmb_req_msg.rq.rq_seq_rq_lun)));
		ipmb_error_reply(master, req_msg, IPMI_TIMEOUT_ERR);
		return;
	}

	buf_rsp = (u8 *) &ipmb_rsp_msg.rs;

	rsp_msg_len = ipmb_msg_len(buf_rsp);

	if (rsp_msg_len < IPMB_LEN_MIN) {
		ipmb_free_seq(master, (GET_SEQ(ipmb_req_msg.rq.rq_seq_rq_lun)));
		ipmb_error_reply(master, req_msg, IPMI_ERR_MSG_TRUNCATED);
		return;
	}

	rsp_msg = ipmb_find_msg(master, (GET_SEQ(ipmb_rsp_msg.rs.rq_seq_rs_lun)));
	if (!rsp_msg) {
		ipmb_free_seq(master, (GET_SEQ(ipmb_req_msg.rq.rq_seq_rq_lun)));
		ipmb_error_reply(master, req_msg, IPMI_ERR_UNSPECIFIED);
		return;
	}

	ipmb_free_seq(master, (GET_SEQ(ipmb_rsp_msg.rs.rq_seq_rs_lun)));

	if (rsp_msg_len < IPMB_RESPONSE_LEN_MIN) {
		ipmb_error_reply(master, rsp_msg, IPMI_ERR_MSG_TRUNCATED);
		return;
	}

	verify_checksum = ipmb_checksum(buf_rsp, rsp_msg_len,
				(u8)(master->client->addr << 1));

	if (verify_checksum) {
		ipmb_error_reply(master, req_msg, IPMI_ERR_UNSPECIFIED);
		return;
	}

	rsp_msg->rsp_size = ipmb_to_smi_len((u8) rsp_msg_len);
	smi_rsp_msg = (struct ipmb_smi_msg *) rsp_msg->rsp;
	smi_rsp_msg->netfn_lun = ipmb_rsp_msg.rs.netfn_rq_lun;
	smi_rsp_msg->cmd = ipmb_rsp_msg.rs.cmd;
	memcpy(smi_rsp_msg->payload, ipmb_rsp_msg.rs.payload,
		ipmb_payload_len((size_t) rsp_msg_len));

	ipmi_smi_msg_received(master->intf, rsp_msg);
}

/*
 * Function called by smi_send in ipmi_msghandler.c
 * It passes request message from ipmitool program
 * to the host's kernel to the receiver via I2C.
 */
static void ipmb_sender(void *data, struct ipmi_smi_msg *msg)
{
	struct ipmb_master *master = data;
	unsigned long flags;

	spin_lock_irqsave(&master->lock, flags);
	if (master->msg_to_send) {
		__ipmb_error_reply(master, msg, IPMI_NODE_BUSY_ERR);
	} else {
		master->msg_to_send = msg;
		schedule_work(&master->ipmb_send_work);
	}
	spin_unlock_irqrestore(&master->lock, flags);
}

static void ipmb_request_events(void *data)
{
}

static void ipmb_set_run_to_completion(void *data,
				bool run_to_completion)
{
}

static void ipmb_poll(void *data)
{
}

static struct ipmi_smi_handlers ipmb_smi_handlers = {
	.owner			= THIS_MODULE,
	.start_processing	= ipmb_start_processing,
	.sender			= ipmb_sender,
	.request_events		= ipmb_request_events,
	.set_run_to_completion	= ipmb_set_run_to_completion,
	.poll			= ipmb_poll,
};

static bool is_ipmb_response(u8 netfn_rq_lun, size_t msg_len)
{
	/*
	 * First, check whether the message has the minimum IPMB response size
	 */
	if (msg_len >= IPMB_RESPONSE_LEN_MIN) {
		/*
		 * Then check whether this is an IPMB request or response.
		 * Responses have an odd netfn while requests have an even
		 * netfn.
		 */
		if ((netfn_rq_lun & NETFN_RSP_BIT) == NETFN_RSP_BIT)
			return true;
	}

	return false;
}

/*
 * This is the callback function used to set this device as a slave
 * and to monitor and handle only IPMB responses.
 *
 * This driver's purpose is to:
 * 1) send IPMB requests,
 * 2) then wait until it receives a response back from the responder.
 *    This callback adds that response into a queue so that it is handled
 *    later in ipmb_receive_rsp.
 */
static int ipmb_slave_cb(struct i2c_client *client,
			enum i2c_slave_event event, u8 *val)
{
	struct ipmb_master *master = i2c_get_clientdata(client);
	u8 *buf;

	spin_lock(&master->lock);

	switch (event) {
	case I2C_SLAVE_WRITE_REQUESTED:
		master->msg_idx = 0;
		memset(&master->rsp, 0,
			sizeof(master->rsp));
		break;

	case I2C_SLAVE_WRITE_RECEIVED:
		buf = (u8 *) &master->rsp;

		if (master->msg_idx >= sizeof(union ipmb_msg))
			break;

		buf[master->msg_idx++] = *val;
		break;

	case I2C_SLAVE_STOP:
		if (is_ipmb_response(master->rsp.rs.netfn_rq_lun,
				master->msg_idx))
			ipmb_handle_response(master);

		master->msg_idx = 0;
		break;

	default:
		break;
	}
	spin_unlock(&master->lock);

	return 0;
}

static unsigned short slave_add = 0x0;
module_param(slave_add, ushort, 0);
MODULE_PARM_DESC(slave_add, "The i2c slave address of the responding device");

static int ipmb_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct ipmb_master *master;
	int ret;

	master = devm_kzalloc(&client->dev, sizeof(struct ipmb_master),
			     GFP_KERNEL);
	if (!master)
		return -ENOMEM;

	spin_lock_init(&master->lock);
	init_waitqueue_head(&master->wait_queue);
	atomic_set(&master->rsp_queue_len, 0);
	INIT_LIST_HEAD(&master->rsp_queue);

	/* Initialize work for sheduling call to ipmb_send_workfn */
	INIT_WORK(&master->ipmb_send_work, ipmb_send_workfn);

	ret = device_property_read_u32(&client->dev, "slave-address",
					&master->rs_sa);
	if (ret) {
		master->rs_sa = slave_add;
		if (master->rs_sa == 0x0) {
			dev_err(&client->dev,
				"Failed to get the responder's address from user\n");
			return ret;
		}
	}

	master->client = client;
	i2c_set_clientdata(client, master);

	ret = i2c_slave_register(client, ipmb_slave_cb);

	if (ret)
		return ret;

	ret = ipmi_register_smi(&ipmb_smi_handlers, master,
				&master->ipmi_id,
				&client->dev,
				(unsigned char)master->rs_sa);

	if (ret)
		i2c_slave_unregister(client);

	return ret;
}

static int ipmb_remove(struct i2c_client *client)
{
	struct ipmb_master *master;

	master = i2c_get_clientdata(client);
	ipmi_unregister_smi(master->intf);
	i2c_slave_unregister(client);

	return 0;
}

static const struct i2c_device_id ipmb_i2c_id[] = {
	{"ipmb-host", 0},
	{},
};
MODULE_DEVICE_TABLE(i2c, ipmb_i2c_id);

static struct i2c_driver ipmb_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "ipmb-host",
	},
	.probe = ipmb_probe,
	.remove = ipmb_remove,
	.id_table = ipmb_i2c_id,
};
module_i2c_driver(ipmb_driver);

MODULE_AUTHOR("Asmaa Mnebhi <asmaa@mellanox.com>");
MODULE_DESCRIPTION("Host IPMB driver");
MODULE_LICENSE("GPL v2");
