#
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sysu8021xclient
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_FIXUP:=autoreconf
PKG_VERSION:=1.0
PKG_RELEASE:=unstable
include $(INCLUDE_DIR)/package.mk

define Package/sysu8021xclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SYSU client by vrqq.srOOrz
  URL:=http://github.com/liuqun/openwrt-feeds-njit/sysu/sysu8021xclient
endef

define Package/sysu8021xclient/description
  SYSU client by vrqq.srOOrz
endef

define Build/Prepare
	$(RM) -r $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/sysu8021xclient/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
endef

$(eval $(call BuildPackage,sysu8021xclient))

