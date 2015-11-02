#include <iostream>
#include "conversation.h"
#include "csismp_limits.h"

using namespace std;
process_conversation(conversation *conv)
{
    switch(conv->type){
        case conversation_type::CONVERSATION_ADD:
            {

            }
            break;
        case conversation_type::CONVERSATION_DEL:
            break;
        case conversation_type::CONVERSATION_ACK:
            break;
        case conversation_type::CONVERSATION_RJT:
            break;
        default:
            break;
    }
}
