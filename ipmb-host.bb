SUMMARY = "IPMB host kernel module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=12f884d2ae1ff87c09e5b7ccc2c4ca7e"

inherit module

do_cve_check[depends] += "${PN}:do_prepare_recipe_sysroot"

SRC_URI = "file://Makefile \
           file://ipmb_host.c \
           file://COPYING \
          "

python do_unpack_append() {
    import shutil
    info = {}

    info['workdir'] = d.getVar('WORKDIR')
    info['s'] = d.getVar('S')
    info['sources'] = d.getVar('SRC_URI').replace("file://", " ")

    for files in info['sources'].split():
      filename = info['workdir'] + '/' + files
      shutil.copy(filename, info['s'])
}

PROVIDES_${PN} =+ " ipmb-host"
