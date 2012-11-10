# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=iwas4gdou
PKG_RELEASE:=1
PKG_VERSION:=1.1
PKG_SOURCE_URL:=https://github.com/downloads/liuqun/iwas4gdou/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

include $(INCLUDE_DIR)/package.mk

define Package/njit8021xclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=GDOU 802.1X client program
  URL:=http://liuqun.github.com/njit8021xclient
  DEPENDS:=+libpcap
endef

define Package/njit8021xclient/description
 802.1X client from Guangdong Ocean University
endef

define Build/Prepare
$(call Build/Prepare/Default)
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/iwas4gdou/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
endef

$(eval $(call BuildPackage,iwas4gdou))
