#include <syslog.h>
#include <string.h>

void log_event(char *user_event) {
    syslog(LOG_INFO, user_event);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        openlog("MyApp", LOG_CONS, LOG_USER);
        log_event(argv[1]);
        closelog();
    }
    return 0;
}