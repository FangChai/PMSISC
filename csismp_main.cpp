#include "csismp_collector.h"
#include "csismp_sender.h"
#include "csismp_process.h"
#include <cstdlib>

int main()
{
        init_sender();
        init_processor();
        start_collector();

        return EXIT_SUCCESS;
}
