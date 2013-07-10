# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=njit8021xclient
PKG_RELEASE:=testing
PKG_VERSION:=1.3
PKG_SOURCE_URL:=@SF/$(PKG_NAME)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MD5SUM:=1b19ac98ba90e18aff7aeefa431753e2

include $(INCLUDE_DIR)/package.mk

define Package/njit8021xclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NJIT 802.1X client program
  URL:=http://liuqun.github.com/njit8021xclient
  DEPENDS:=+libpcap
  PKG_BUILD_DEPENDS:=+libopenssl
endef

define Package/njit8021xclient/Default/description
 802.1X client from Nanjing Institude of Technology,
 compatable with H3C iNode 802.1X client.
 Support H3C/iNode's private authentication protocol V2.40-V3.60
endef

CONFIGURE_ARGS += \
	--program-prefix="njit-" \
	$(NULL)

define Build/Prepare
$(call Build/Prepare/Default)
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/njit8021xclient/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
endef

define Package/njit8021xclient/conffiles
/etc/config/njit8021xclient.conf
endef

define Package/njit8021xclient-web
  SECTION:=net
  CATEGORY:=Network
  TITLE:=LuCI pages for NJIT 802.1X client
  URL:=http://sourceforge.net/projects/njit8021xclient/
  DEPENDS:=njit8021xclient
  PKGARCH:=all
endef

define Package/njit8021xclient-web/description
  $(call Package/njit8021xclient/Default/description)
  This package contains LuCI web pages of njit8021xclient.
  It will help you to set your 802.1X login password.
endef

define Package/njit8021xclient-web/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src-gui/luci/luci_controller_njit.lua \
		$(1)/usr/lib/lua/luci/controller/njit.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src-gui/luci/njit.lua \
		$(1)/usr/lib/lua/luci/model/cbi/njit.lua
endef


define Package/njit8021xclient/description
  $(call Package/njit8021xclient/Default/description)
  This package contains only the main program njit-client.
endef

$(eval $(call BuildPackage,njit8021xclient))
$(eval $(call BuildPackage,njit8021xclient-web))
