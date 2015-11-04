CPP_FLAGS := --std=c++11
DEBUG := -g
LIBS := -lpthread -lpcap
SOURCES := csismp_main.cpp csismp_collector.cpp \
	csismp_sender.cpp csismp_process.cpp \
	timer.cpp print_session.cpp
HEADERS := csismp_collector.h csismp_sender.h \
	csismp_process.h timer.h\
	mac_configure.h

all : SeedCup.exe

SeedCup.exe : $(SOURCES) $(HEADERS)
	g++ $(CPP_FLAGS) $(SOURCES) $(HEADERS) $(LIBS) $(DEBUG) -o SeedCup.exe
