# 
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2 or later
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mentohust
PKG_VERSION:=0.3.1
PKG_RELEASE:=openwrt20120923

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:= \
  http://code.google.com/p/mentohust/ \
  http://github.com/downloads/liuqun/mentohust/ \
  $(NULL)
PKG_MD5SUM:=4eecde99c0152fb2f9def285f57e252c

include $(INCLUDE_DIR)/package.mk

define Package/mentohust
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OpenWRT 802.1X client for RuiJie V2/V3
  URL:=http://github.com/microcaicai/mentohust
  DEPENDS:=
endef

define Package/njit8021xclient/description
  Compatable 802.1X client.
  Currently ONLY support RuiJie V2 private authentication protocol
  MentoHUST-0.3.4 will support RuiJie V3 private authentication protocol
endef

define Build/Prepare
$(call Build/Prepare/Default)
endef

CONFIGURE_ARGS += \
	--disable-debug \
	$(NULL)
define Build/Configure
$(call Build/Configure/Default)
endef

define Package/mentohust/install
$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(1)
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
