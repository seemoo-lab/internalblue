include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = internalbluedprefs

internalbluedprefs_FILES = IBDRootListController.m
internalbluedprefs_INSTALL_PATH = /Library/PreferenceBundles
internalbluedprefs_FRAMEWORKS = UIKit
internalbluedprefs_PRIVATE_FRAMEWORKS = Preferences
internalbluedprefs_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences$(ECHO_END)
	$(ECHO_NOTHING)cp entry.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/internalbluedprefs.plist$(ECHO_END)
