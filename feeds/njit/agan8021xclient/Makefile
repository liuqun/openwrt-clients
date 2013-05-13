# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=agan8021xclient
PKG_VERSION:=1.2
PKG_RELEASE:=testing
PKG_SOURCE_URL:=@SF/$(PKG_NAME)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MD5SUM:=d3df4ad26d1ed773e2a20d84036f8adc
include $(INCLUDE_DIR)/package.mk

define Package/agan8021xclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AGanNo2's 802.1X client program for H3C V2.20-0247
  URL:=http://sourceforge.net/projects/agan8021xclient
  DEPENDS:=+libpcap +libnet1
  PKG_BUILD_DEPENDS:=+libopenssl
endef

define Package/agan8021xclient/description
 AGanNo2's 802.1X client program for H3C V2.20-0247
endef

define Build/Prepare
$(call Build/Prepare/Default)
endef


CONFIGURE_VARS:= \
  CPPFLAGS="$(TARGET_CPPFLAGS) -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/lib/libnet-1.1.x/include" \
  LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/usr/lib/libnet-1.1.x/lib" \
  $(NULL)

CONFIGURE_ARGS += \
  --with-pcap=$(STAGING_DIR)/usr \
  $(NULL)

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/agan8021xclient/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
endef

$(eval $(call BuildPackage,agan8021xclient))
