# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=oh3c
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://github.com/downloads/liuqun/OH3C/
PKG_MD5SUM:=2e65cdd95524d2a63ada5cce3eb62e2a

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/oh3c
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OH3C 802.1X client
  URL:=http://github.com/nanpuyue/oh3c
  DEPENDS:=+python
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/oh3c/install
$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(1)
endef

$(eval $(call BuildPackage,oh3c))
