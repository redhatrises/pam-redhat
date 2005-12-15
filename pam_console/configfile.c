#include <string.h>
#include <stdlib.h>
#include "configfile.h"

void *
_do_malloc(size_t req)
{
        void *ret;
        ret = malloc(req);
        if (!ret) abort();
        return ret;
}

#include "configfile.lex.c"
#include "configfile.tab.c"

