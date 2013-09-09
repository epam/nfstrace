#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include "plugin_api.h"

int main(int argc, char **argv) 
{
    void *lib_handle;
    char *error;

    lib_handle = dlopen("/home/developer/cpp/plugins/libplugin.so", RTLD_LAZY);
    if (!lib_handle) 
    {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

    create_t create = (create_t) dlsym(lib_handle, "create");
    if ((error = dlerror()) != NULL)  
    {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }

    (*create)("opt=32,val=MyValue");

    dlclose(lib_handle);
    return 0;
}
