# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=agan8021xclient
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_SOURCE_URL:=@SF/$(PKG_NAME)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MD5SUM:=

include $(INCLUDE_DIR)/package.mk

define Package/agan8021xclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AGanNo2's 802.1X client program for H3C V2.20-0247
  URL:=http://github.com/liuqun/
  DEPENDS:=+libpcap +libnet1 +libopenssl
endef

define Package/agan8021xclient/description
 AGanNo2's 802.1X client program for H3C V2.20-0247
endef

define Build/Prepare
$(call Build/Prepare/Default)
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/agan8021xclient/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
endef

$(eval $(call BuildPackage,agan8021xclient))
