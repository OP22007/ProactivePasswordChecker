#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<time.h>
#include<unistd.h>
#include<math.h>
struct User{
    char username[50];
    char dob[11];
    char pass_file[11];
    char pass[10][21];
};
const char special_char[] = ".@!#$%^&*-_";
int special_char_check(char pass[]){
    for(int i=0;i<strlen(pass);i++){
        if(strchr(special_char,pass[i]))return 1;
    }
    return 0;
}
void get_password(char pass_file[11],char pass[10][21],int* n){
    FILE* file = fopen(pass_file,"r");
    if(!file){
        printf("Password File doesnt exist\n");
        exit(1);
    }
    while (fscanf(file,"%s",pass[*n])!=EOF && *n<10) {
        (*n)++;
    }
    fclose(file);
}
void save_passwords(char* filename,char passwords[10][21],int prev){
    FILE* file = fopen(filename,"w");
    if(!file){
        printf("File couldnt be opened\n");
        exit(1);
    }
    for(int i=0;i<prev;i++){
        fprintf(file,"%s\n",passwords[i]);
    }
    fclose(file);
}
void get_users(struct User users[],int *n){
    FILE* file = fopen("masterfile.txt","r");
    if(!file){
        printf("MasterFile couldnt be opened\n");
        exit(1);
    }
    fscanf(file,"%s %s %s",users[*n].username,users[*n].dob,users[*n].pass_file);
    while(fscanf(file,"%s %s %s",users[*n].username,users[*n].dob,users[*n].pass_file)!=EOF){
        (*n)++;
    }
    fclose(file);
}
void backoff_timer(int time) {
    for (int i=time;i>0;i--) {
        printf("\rWait for %d seconds....",i);
        fflush(stdout);
        sleep(1);
    }
    printf("\r                 \r");
}
void to_lowercase(char *s) {
    for (int i=0;s[i];i++){
        s[i]=tolower((unsigned char)s[i]);
    }
}
int valid_password_checker(char new_pass[],struct User user,int prev,int attempt,char password[][21]){
    int violations[8];
    for(int i=0;i<8;i++)violations[i]=0;

    // Length >= 12
    if(strlen(new_pass)<12)violations[0]=1;

    // Atleast 1 uppercase
    int upper=0;
    for(int i=0;i<strlen(new_pass);i++){
        if(isupper(new_pass[i])){upper=1;break;}
    }
    if(!upper)violations[1]=1;

    // Atleast 1 lowercase
    int lower=0;
    for(int i=0;i<strlen(new_pass);i++){
        if(islower(new_pass[i])){lower=1;break;}
    }
    if(!lower)violations[2]=1;

    // Atleast 1 digit
    int digit=0;
    for(int i=0;i<strlen(new_pass);i++){
        if(isdigit(new_pass[i])){digit=1;break;}
    }
    if(!digit)violations[3]=1;

    // Atleast 1 special character from the given set of characters
    if(!special_char_check(new_pass))violations[4]=1;
    
    // Password contains more than 4 characters from previous passwords
    int flag=0;
    int mx2=0;
    for (int i=0;i<prev;i++){
    int mx = 0;
    for (int j = 0; j < strlen(password[i]); j++) {
        for (int k = 0; k < strlen(new_pass); k++) {
            int dig = 0;
            // Compare substrings starting from password[i][j] and new_pass[k]
            // returns the max number of charcters matching between the new_pass and any of the previous passwords
            while (j+dig<strlen(password[i]) && k+dig<strlen(new_pass) && tolower(password[i][j+dig]) == tolower(new_pass[k+dig])) {
                dig++;
            }
            if (dig > mx)mx = dig;
        }
    }
    if (mx > mx2) {
        mx2 = mx;
    }
    mx = 0;
}
    if(mx2>4)violations[5]=1;

    // Password contains username or firstname or surname
    char fname[50],surname[50];
    sscanf(user.username,"%[^.].%s",fname,surname);
    int fands=0,f=0,s=0;
    char lower_new_pass[21];
    char lower_fname[50];
    char lower_surname[50];
    strcpy(lower_surname, surname);
    strcpy(lower_new_pass, new_pass);
    strcpy(lower_fname, fname);
    to_lowercase(lower_new_pass);
    to_lowercase(lower_fname);
    to_lowercase(lower_surname);
    if (strstr(lower_new_pass,lower_fname) && strstr(lower_new_pass,lower_surname))fands=1;
    else if(strstr(lower_new_pass,lower_fname))f=1;
    else if(strstr(lower_new_pass,lower_surname))s=1;
    if(fands||f||s)violations[6]=1;

    // Password contains more than 3 consecutive digits of dob
    char dob_digits[9];
    sprintf(dob_digits,"%c%c%c%c%c%c%c%c",user.dob[0],user.dob[1],user.dob[3],user.dob[4],user.dob[6],user.dob[7],user.dob[8],user.dob[9]);
    int len=strlen(new_pass);
    // for(int i=0;i<strlen(new_pass)-3;i++){
    //     if(strstr(dob_digits,new_pass+i))dig=4;
    // }
    // if(dig==4)violations[7]=1;
    int maxi=0;
    for(int i=0;i<8;i++)
    {
        for(int j=0;j<len;j++)
        {
            int dig=0;
            while(i+dig<8 && j+dig<len && isdigit(new_pass[j+dig]) && dob_digits[i+dig]==new_pass[j+dig])
            {
                dig++;
            }
            if(dig>maxi)maxi=dig;

        }
    }
    if(maxi>=4)violations[7]=1;
    if(attempt<4){
        if(violations[0])printf("Password does not contain a minimum of 12 characters.\n");
        if(violations[1])printf("Password does not contain at least one uppercase letter.\n");
        if(violations[2])printf("Password does not contain at least one lowercase letter.\n");
        if(violations[3])printf("Password does not contain at least one digit.\n");
        if(violations[4])printf("Password does not contain at least one of the allowed special characters.\n");
        if(violations[5])printf("Password contains %d characters consecutively similar to one of the past 10 passwords.\n",mx2);
        if(violations[6]&&fands)printf("Password contains name and surname portions of username.\n");
        if(violations[6]&&f)printf("Password contains name portion of the username.\n");
        if(violations[6]&&s)printf("Password contains surname portion of username.\n");
        if(violations[7])printf("Password contains %d digits consecutively similar to the date of birth.\n",maxi);
    }
    for(int i=0;i<8;i++){
        if(violations[i]==1)return 0;
    }
    return 1;
}
int main(){
    struct User users[11];
    int no_of_users=0;
    get_users(users,&no_of_users);
    // printf("%s",users[0].username);
    char username[50],pass[21];
    int auth = 0;
    printf("Enter username: ");
    scanf("%s",username);
    printf("%s\n",username);
    int idx = -1;
    for(int i=0;i<no_of_users;i++){
        if(strcmp(users[i].username,username)==0){
            idx=i;
            break;
        }
    }
    printf("%d\n",idx);
    if(idx==-1){
        printf("Username not found.\n");
        return 1;
    }
    char pass_file[11];
    strcpy(pass_file,users[idx].pass_file);
    char passwords[10][21];
    int no_of_pass=0;
    get_password(pass_file,passwords,&no_of_pass);
    printf("Number of passwords are %d\n",no_of_pass);

    // Login Attempts
    int attempts=0;
    while(attempts<3 && !auth){
        printf("Enter password: ");
        scanf("%s",pass);
        if(strcmp(pass,passwords[0])==0){
            auth=1;
            printf("Login Successful.\n");
        }else{
            printf("Wrong password! Enter password again:\n");
            attempts++;
        }
    }
    if(!auth){
        printf("Wrong password entered 3 times. Application exiting...\n");
        return 1;
    }
   // return 0;

    // Password change attempts
    int valid=0;
    attempts=0;
    while(attempts<4 && !valid){
        printf("Enter your new password (%d attempt): ",attempts+1);
        scanf("%s",pass);
        if(valid_password_checker(pass,users[idx],no_of_pass,attempts+1,passwords)){
            printf("Password changed successfully.\n");
            for(int i=9;i>0;i--){
                strcpy(passwords[i],passwords[i-1]);
            }
            strcpy(passwords[0],pass);
            save_passwords(pass_file,passwords,no_of_pass<10?no_of_pass+1:10);
            valid=1;
        }else{
            attempts++;
            if(attempts==4)break;
            if(attempts==1){
                backoff_timer(8);
            }else if(attempts==2){
                backoff_timer(16);
            }else if(attempts==3){
                backoff_timer(32);
            }
        }
    }
    if(!valid)
    {
        printf("Failed to enter a valid password in 4 attempts.\n");
    }
    
    return 0;
}