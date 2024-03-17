TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.c

LIBS += -lpcap


DISTFILES += \
    pcap-test.pro.user
