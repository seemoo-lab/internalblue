include $(THEOS)/makefiles/common.mk

TOOL_NAME = internalblued

internalblued_FILES = main.m ios-proxy.m
internalblued_CFLAGS = -fobjc-arc
internalblued_CODESIGN_FLAGS = -Sent.xml

include $(THEOS_MAKE_PATH)/tool.mk

#SUBPROJECTS += internalbluedprefs
include $(THEOS_MAKE_PATH)/aggregate.mk

after-internalblued-stage::
	$(ECHO_NOTHING)$(FAKEROOT) chown root:wheel $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.ttdennis.internalblued.plist$(ECHO_END)
