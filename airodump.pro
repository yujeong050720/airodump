TEMPLATE = app
TARGET = airodump
CONFIG += console c++17
CONFIG -= app_bundle
LIBS += -lpcap

SOURCES += main.cpp \\
           ap.cpp

HEADERS += ap.h \\
           wireless.h
