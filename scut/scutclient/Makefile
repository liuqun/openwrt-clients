#
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=scutclient
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_FIXUP:=autoreconf
PKG_VERSION:=1.0
PKG_RELEASE:=unstable
include $(INCLUDE_DIR)/package.mk

define Package/scutclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SCUT client by Forward
  URL:=http://github.com/liuqun/openwrt-feeds-njit/scut/scutclient
  DEPENDS:=+libpcap
  PKG_BUILD_DEPENDS:=+libopenssl
endef

define Package/scutclient/description
  SCUT client by Forward
endef

define Build/Prepare
	$(RM) -r $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

CONFIGURE_ARGS += \
  --program-prefix="scut" \
  $(NULL)
CONFIGURE_VARS:= \
  CPPFLAGS="$(TARGET_CPPFLAGS) -I$(STAGING_DIR)/usr/include" \
  LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib" \
  $(NULL)

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/scutclient/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
endef

$(eval $(call BuildPackage,scutclient))

