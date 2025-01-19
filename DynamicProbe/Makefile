ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DynamicProbe

DynamicProbe_FILES = Tweak.xm ProbeMenuViewController.m
DynamicProbe_FRAMEWORKS = UIKit AudioToolbox
DynamicProbe_CFLAGS = -fobjc-arc -Wno-error=expansion-to-defined -Wno-error=deprecated-declarations -Wno-error=format

ifdef DYLIB
	DynamicProbe_LDFLAGS = -dynamiclib
	DynamicProbe_CODESIGN_FLAGS = -Sent.xml
endif

include $(THEOS_MAKE_PATH)/tweak.mk

dylib::
	$(MAKE) DYLIB=1
	mkdir -p $(THEOS_STAGING_DIR)/DynamicProbe
	mv $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/DynamicProbe.dylib $(THEOS_STAGING_DIR)/DynamicProbe/
	codesign -fs "iPhone Developer" --entitlements ent.xml $(THEOS_STAGING_DIR)/DynamicProbe/DynamicProbe.dylib