#include "csismp_collector.h"
#include "csismp_sender.h"
#include "csismp_process.h"

int main()
{
        init_sender();
        init_processor();
        start_collector();

        return 0;
}
