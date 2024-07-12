#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define KEY_MAX_LENGTH 18
#define KEY_MIN_LENGTH 8
#define ADMIN_PASS "admin"
#define ADMIN_PASS_LEN 7
#define BUFSIZE 0x18

typedef struct info {
    char Wifi_Key[KEY_MAX_LENGTH];
    int len;
    bool IS_WIFI_CONNECTED;
    bool interface[3];
} info;

struct info infos= {
        .Wifi_Key = {0},
        .len = KEY_MAX_LENGTH,
        .IS_WIFI_CONNECTED = false,
        .interface = {true, true, true}
};


static void remove_newline(char* str)
{
    char* last = str + strlen(str) - 1;

    if (last >= str && *last == '\n')
        *last = 0;
}

int show_network_interface() {
    printf("Interface\n");
    printf("\teth0 is %s\n", infos.interface[0] ? "up": "down");
    printf("\tl0 is %s\n", infos.interface[1] ? "up": "down");
    printf("\twlan0 is %s\n", infos.interface[2] ? "up": "down");
    return 0;
};

int msg_interface(int num, char *interface) {
    if (num < 0) {
        printf("Interface does not exist\n");
        return 1;
    }
    infos.interface[num] = !infos.interface[num];
    printf("Interface %s is now : %s\n", interface, infos.interface[num] ? "up": "down");
    return 0;
}

int change_interface() {
    char interface[BUFSIZE];
    int err = 0;
    printf("Which interface would you change the state ?\n");
    printf("#>");
    fgets(interface, BUFSIZE, stdin);
    remove_newline(interface);
    if (strncmp(interface, "eth0", strlen("eth0")) == 0)
        err = msg_interface(0, interface);
    else if (strncmp(interface, "l0", strlen("l0")) == 0)
        err = msg_interface(1, interface);
    else if (strncmp(interface, "wlan0", strlen("wlan0")) == 0)
        err = msg_interface(2, interface);
    else
        err = msg_interface(-1, interface);

    return err;
}

void Connect_NAS(){
    printf("Loki's NAS connected in path /flag/!\n");
};

bool verify(char buf[]) {
    size_t len;
    remove_newline(buf);
    len = strlen(buf);

    printf("Trying to connect to Wifi ...\n");
    if (len < KEY_MIN_LENGTH) {
        printf("Too short : \n");
        printf(buf);
        return false;
    }
    else if (strncmp(buf, infos.Wifi_Key, len) != 0) {
        printf("Wrong password\n");
        return false;
    }
    else {
        infos.IS_WIFI_CONNECTED = true;
        printf("You are connected !\n");
        return true;
    }
}

void Connect_TO_WIFI(){
    char buf[KEY_MAX_LENGTH];
        if (infos.IS_WIFI_CONNECTED) {
            printf("You are already connected\n");
        }
        else {
            printf("\nEnter Wifi Password : \n");
            printf("#>");

            // ROP
            fgets(buf, infos.len, stdin);
            infos.IS_WIFI_CONNECTED = verify(buf);

        }
};

void Change_WIFI_Key() {
    char buf[BUFSIZE] = {0};
    size_t len;

    printf("Enter new password\n");
    printf("#ADM#>");
    fgets(buf, BUFSIZE, stdin);
    len = strlen(buf);
    infos.len = len < KEY_MAX_LENGTH ? len : KEY_MAX_LENGTH;

    if (KEY_MIN_LENGTH > len) {
        printf("Password does not meet the requirement\n");
        return;
    }

    // BUFSIZE != KEY_MAX_LEN
    strncpy(infos.Wifi_Key, buf, len);

    printf("New password is : %s\n", infos.Wifi_Key);
    return;

};
void Admin_Menu(void) {
    int choice;
    while (1) {
        printf("\033[0;31m"); // Séquence d'échappement ANSI pour la couleur rouge en gras
        printf("*** Admin Menu ***\n");
        printf("0 - QUIT\n");
        printf("1 - Quit admin menu\n");
        printf("2 - Change WIFI Key\n");
        printf("#ADM#>");
        fflush(stdout);
        choice = getchar();
        getchar(); // Get /n
        switch (choice) {
            case '2' :
                Change_WIFI_Key();
                break;
            case '1' :
                printf("\033[0m"); // Réinitialisation de la couleur à celle par défaut
                return;
            case '0' :
            default:
                printf("\033[0m"); // Réinitialisation de la couleur à celle par défaut
                exit(1);
        }
    }

}


int verify_admin_pwd(int test, char *pwd) {

    if (strcmp(pwd, ADMIN_PASS) != 0) {
        printf("Bad pwd\n");
        return 1;
    }
    printf("Hello you are logged as Admin\n");
    Admin_Menu();
    return 0;
}

int Log_In(){
    char pwd[ADMIN_PASS_LEN] = {0};
    printf("Enter Admin password: \n");
    printf("#>");

    fgets(pwd,ADMIN_PASS_LEN, stdin);
    remove_newline(pwd);
    return verify_admin_pwd(1, pwd);

};




void User_Menu(void) {
    while (1) {
        int choice;

        printf("0 - QUIT\n");
        printf("1 - Show Network Interface\n");
        printf("2 - Shutdown or no shutdown Interface\n");
        printf("3 - Connect to WIFI\n");
        printf("4 - Connect to NAS\n");
        printf("5 - Log In as Admin\n");
        printf("#>");
        fflush(stdout);

        choice = getchar();
        getchar(); // Get /n
        switch (choice) {
            case '1' :
                show_network_interface();
                break;
            case '2' :
                change_interface();
                break;
            case '3' :
                Connect_TO_WIFI();
                break;
            case '4' :
                Connect_NAS();
                break;
            case '5' :
                Log_In();
                break;
            case '0' :
            default:
                exit(0);
        }
    }

}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("*** Welcome to Loki routeur ***\n");
    User_Menu();
    return 0;
}