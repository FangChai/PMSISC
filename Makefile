CPP_FLAGS := --std=c++11
DEBUG := -g -D DEBUG
LIBS := -lpthread -lpcap
SOURCES := csismp_main.cpp csismp_collector.cpp \
	csismp_sender.cpp csismp_process.cpp \
	csismp_timer.cpp print_session.cpp
HEADERS := csismp_collector.h csismp_sender.h \
	csismp_process.h csismp_timer.h\
	csismp_config.h

all : SeedCup.exe

SeedCup.exe : $(SOURCES) $(HEADERS)
	g++ $(CPP_FLAGS) $(SOURCES) $(HEADERS) $(LIBS) $(DEBUG) -o SeedCup.exe
