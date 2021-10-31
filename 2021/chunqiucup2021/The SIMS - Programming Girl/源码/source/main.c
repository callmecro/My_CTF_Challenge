#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

struct Player {
	char name[24];
	uint32_t age;
	uint32_t sex;
	uint32_t money;
	uint32_t charm;
	uint32_t have_car;
	uint32_t have_house;
	uint32_t have_married;
	uint32_t have_quality_life;
	struct MaleFriend *husband;
} player;

struct MaleFriend {
	char name[16];
	uint64_t score;
	uintptr_t *ptr;
} *male_friends[10];

uint32_t number = 0;

struct Date {
	uint64_t day;
	uintptr_t* weather;
} date;

char weather[7][10] = {
	"Sunny", "Cloudy", "Rainy", "Snowy", "Thunder", "Greasy", "Windy"
};

char banner[] = ""
".================================================================.\n"
"||       _____ _            _____ ________  ___ _____           ||\n"
"||       |_   _| |          /  ___|_   _|  \\/  |/  ___|         ||\n"
"||         | | | |__   ___  \\ `--.  | | | .  . |\\ `--.          ||\n"      
"||         | | | '_ \\ / _ \\  `--. \\ | | | |\\/| | `--. \\         ||\n"
"||         | | | | | |  __/ /\\__/ /_| |_| |  | |/\\__/ /         ||\n"
"||         \\_/ |_| |_|\\___| \\____/ \\___/\\_|  |_/\\____/          ||\n"
"||                                                              ||\n"
"|'--------------------------------------------------------------'|\n"
"||                   __ __   /__)_   _ _ _ _  _  '  _   _ '_ /  ||\n"
"||                          /   / ()(// (///)//)//)(/  (/// (   ||\n"
"||                                 _/             _/   _/       ||\n"
"|'=============================================================='|\n"
"||                                .::::.                        ||\n"
"||                              .::::::::.                      ||\n"
"||                              :::::::::::                     ||\n"
"||                              ':::::::::::..                  ||\n"
"||                               :::::::::::::::                ||\n"
"||                                '::::::::::::::.              ||\n"
"||                                  .::::::::::::::::.          ||\n"
"||                                .::::::::::::..               ||\n"
"||                               ::::::::::::::''               ||\n"
"||                   .:::.       '::::::::''::::                ||\n"
"||                 .::::::::.      ':::::'  '::::               ||\n"
"||                .::::':::::::.    :::::    '::::.             ||\n"
"||              .:::::' ':::::::::. :::::.     ':::.            ||\n"
"||            .:::::'     ':::::::::.::::::.      '::.          ||\n"
"||          .::::''         ':::::::::::::::'       '::.        ||\n"
"||         .::''              '::::::::::::::'        ::..      ||\n"
"||      ..::::                  ':::::::::::'         :'''`     ||\n"
"||   ..''''':'                    '::::::.'                     ||\n"
"|'=============================================================='|\n"
"||                                        have fun with it ^_^! ||\n"
"||                                             chunqiu cup 2021 ||\n"
"'================================================================'\n"
"\n";

char tip[] = ""
	"| Day:%-3u | Weather:%-7s | It's a full day |\n"
	"| Show our programming girl: %-16s |\n"
	"| Money:%-10u| Charm:0x%-3x| C/H/M/Q:%u%u%u%u |\n";

char menu[] = "\n"
"What would you like to do today?\n"
"1. Working\n"
"2. Improving yourself\n"
"3. Make new friends\n"
"4. Visit friends\n"
"5. Buying\n"
"6. Get married\n"
"default. lying flat\n"
"Choice: "
;

void init_buffering();
void init();
uint32_t read_int();
uint32_t read_n(char *buf, uint64_t len);
uint32_t write_n(char *buf);

uint32_t new_date(uint64_t i);

uint32_t working();
uint32_t improving();
uint32_t make_friends();
uint32_t visit_friends();
uint32_t buying();
uint32_t lying_flat();
uint32_t get_married();
uint32_t quality_life();


int main(int *argc, char *argv[]){
	init_buffering();
	init();

	for (uint64_t i = 1; i < 100; i++) {
		new_date(i);
		uint32_t op = read_int();
		switch(op) {
			case 1: working(); break;
			case 2: improving(); break;
			case 3: make_friends(); break;
			case 4: visit_friends(); break;
			case 5:	buying(); break;
			case 6:	get_married(); break;
			case 999: quality_life(); break;
			default: lying_flat();
		}

	}

	return 0;
}

void init_buffering() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	srand(time(NULL));
	memset(&player, 0, sizeof(struct Player));
	memset(&date, 0, sizeof(struct Date));
}

void init() {
	write_n(banner);
	write_n("Hello, Welcome to the SIMS - Programming Girl\n");
	write_n("You are required to provide relevant personal information as required by laws and regulations\n");
	
	write_n("Name: ");
	read_n(player.name, 15);

	write_n("Age: ");
	player.age = read_int();

	if (player.age < 18) {
		write_n("Sorry, this game is not suitable for minors!\n");
		exit(-1);
	}

	write_n("Sex (1:man,2: woman): ");
	player.sex = read_int();

	if (player.sex != 2 ) {
		write_n("No! You are not a girl! Go away!\n");
		exit(-1);
	}

	player.money = 1000;
	player.charm = 0x10;

	printf("\nHello! %s ^_^\n", player.name);
	write_n("Welcome to our new SIMS. This version is specially designed for female programmer\n");
	write_n("In this life, you're a single female programmer working in a big city!\n");
	write_n("You struggle in a big company, working hard every day. But even then, you only have $1000 to accumulate at the moment because of the high cost of living in a big city\n\n");
	
	write_n("Now that you're 26 years old, it's time to think about your life.\n");
	write_n("Here, you have two life goals to accomplish:\n");
	write_n("1. Get married. You have to make male friends as many as you want. It's up to you, but you can choose only one to marry together.\n");
	write_n("2. Quality Life. If you want to be a high-quality human female, you must first have a house, a car and a certain amount of wealth.\n\n");

	write_n("Now, let me introduce you to the rules of the game.\n");
	write_n("First, you have to work hard to make money first, then you will have the capital to survive:\n");
	write_n("1. Serious Work.(Low pay but steady)\n");
	write_n("2. Outsourcing.(High pay but high risk)\n\n");

	write_n("Next, if you're looking for a male friend, you need to take care of yourself to make yourself more attractive.\n");
	write_n("1. Aesthetic Nursing.\n");
	write_n("2. Yoga Fitness.\n");
	write_n("3. Temperament cultivation.\n\n");

	write_n("Then, if you want to live a high quality single life, you need to buy a car, buy a house and accumulate some wealth.\n");
	write_n("1. Buy Car.\n");
	write_n("2. Buy House.\n\n");

	write_n("However, don't forget that your daily life also requires money, and life's unexpected events can take a toll on your wealth.\n");
	write_n("So, go,go,go, Our programming girl.Go to live your own life!\n\n\n");

}

uint32_t write_n(char *buf) {
	uint32_t len = strlen(buf);
	return write(1, buf, len);
}

uint32_t read_n(char *buf, uint64_t len) {
	char *c[2] = {0};

	for (uint32_t i = 0; i < len; i++) {
		if (read(0, c, 1) <= 0) {
			puts("Read Error!");
			exit(-1);
		}
		if (c[0] == '\n') {
			buf[i] = 0;
			break;
		}
		buf[i] = c[0];
	}
}

uint32_t read_int() {
	char buf[0x20];
	memset(buf, 0, 0x20);
	read_n(buf, 20);
	return atoi(buf);
}

uint32_t new_date(uint64_t i) {
	date.day = i;
	date.weather = weather[rand() % 7];

	player.money -= 20;

	printf(tip, date.day, date.weather, player.name, player.money, player.charm, player.have_car, player.have_house, player.have_married, player.have_quality_life);

	write_n(menu);
}

uint32_t working() {
	write_n(
		"Working people, working soul, we are top brass!\n"
		"Please choice your work:\n"
		"1. Serious Work.\n"
		"2. Outsourcing.\n"
		"Choice: "
	);
	uint32_t op = read_int();
	uint32_t date_salary = 0;

	if (op == 1) {
		date_salary = 40 + (rand() % 10);
		printf("Your salary today is $%u ^_^\n", date_salary);
	}
	else if (op == 2){
		if (rand() % 100 >= 40) {
			date_salary = 100 + (rand() % 50);
			printf("Congratulations, you made $%u from outsourcing!\n", date_salary);
		} else {
			date_salary = -100 - (rand() % 50);
			printf("There was an accident with your outsourcing job, which make you lost $%u!\n", -date_salary);
		}

	} else {
		write_n("$50 will be deducted from salary because of your absent without reason!\n");
		date_salary = -50;
	}

	player.money += date_salary;
	return player.money;
}

uint32_t improving() {
	if (player.charm >= 520) {
		return write_n("Wow, you already too shine, so don't improve yourself, give other girls chances!\n");
	}

	write_n(""
		"Improve yourself to attract others boys!\n"
		"Please choice your activity:\n"
		"1. Aesthetic Nursing.($2000)\n"
		"2. Yoga Fitness.($5000)\n"
		"3. Temperament cultivation.($10000)\n"
		"Choice: "
	);
	uint32_t op = read_int();
	uint32_t custom = 0;
	uint32_t charm = 0;

	switch(op) {
		case 1: custom = 2000; charm = 0x8; break;
		case 2: custom = 5000; charm = 0x10; break;
		case 3: custom = 10000; charm = 0x20; break;
		default: return write_n("This activity is not open at the moment!\n");
	}

	if (player.money >= custom) {
		player.money -= custom;
		player.charm += charm;
		if (player.charm >= 520) {
			player.charm = 520;
			printf("Wow, you've hit your charm Max!\n", charm);
			return write_n("\n");
		}

		printf("Wow, you've increased your charm %u points!", charm);
		return write_n("\n");
	}

	return write_n("Sorry, you don't have enough money to do this!\n");
}

uint32_t make_friends() {
	if (number >= 10) {
		return write_n("Don't go overboard, girl!\n\n");
	}

	write_n(""
		"Get out more, you will have a good encounter!\n"
		"Please choice where you want to go:\n"
		"1. Bar.\n"
		"2. Park.\n"
		"3. Matchmaking.\n"
		"Choice: "
	);

	uint32_t op = read_int();

	if (op == 1) {
		return write_n(""
			"You go to a bar, and while you're drinking, you meet a cute guy.\n"
			"He talks to you, seems nice and wants to socialize with you.\n"
			"But based on your own experience watching idol dramas, you can find this guy is a zhanan!\n"
			"So, you reject him and go home.\n\n"
			);
	} 
	else if (op == 2) {
		player.money -= 200;
		return write_n(""
			"You alone, go to the park to take a walk.\n"
			"Unfortunately, you met a mugger who robbed you of 200 dollars.\n\n"
			);
	} 
	else if (op == 3) {
		write_n(""
			"You come to the dating club and there are a lot of nice boys.\n"
			"Now, tell me, what do you look for in a partner: "
			);
		uint32_t score = read_int();
		uint32_t idx;

		if (score > player.charm) {
			return write_n(
				"Don't Aim High But Accomplish Little, my girl.\n"
				"If you want a good partner, you have to be good enough yourself!\n\n");
		}

		for (idx = 0; idx < 10; idx++) {
			if (male_friends[idx] == NULL) break;
		}

		male_friends[idx] = (struct MaleFriend*)calloc(1, 0x20);

		male_friends[idx]->score = score;

		write_n("Give your new male friend a nickname: ");
		read_n(male_friends[idx]->name, 0x10);
		

		male_friends[idx]->ptr = malloc(score);

		write_n("For both of you, a little greeting: ");
		read_n(male_friends[idx]->ptr, score);
		number++;

		return write_n("Congratulations and best wishes for your two!\n\n");
	}
	else {
		return write_n(""
			"You alone, go to the park to take a walk.\n"
			"Unfortunately, you met a mugger who robbed you of 200 dollars.\n\n"
			);
	}

}

uint32_t visit_friends() {
	write_n("Relationships need to rely on their own efforts to maintain.!\n");
	write_n("Please choose your male friends to visit: ");

	uint32_t idx = read_int();
	if (idx >= number || !male_friends[idx]) {
		return write_n("I'm sorry, but he's not your friend yes!\n\n");
	}

	write_n(
		"Do you want to do something with him?\n"
		"1. Shopping\n"
		"2. Chatting\n"
		"3. Break off\n"
		"Choice: "
	);
	uint32_t op = read_int();

	if (op == 1) {
		player.money += 20;
		return write_n("You and your male friend spent the whole day shopping, shopping and eating together, saving money on dinner today!\n\n");
	}
	else if (op == 2) {
		return write_n("You had a long chat with your male friend, and both had a good day!\n\n");
	}
	else if (op == 3){
		free(male_friends[idx]->ptr);
		free(male_friends[idx]);
		return write_n("It seems that you don't get along particularly well with your male friend.\n"
			"Now, your friendship is officially over and you will never talk to each other again.\n\n");
	}
	else {
		return write_n("You don't have a male friend yet!\n\n");
	}
}

uint32_t buying() {
	write_n(
		"Women should invest more in themselves.\n"
		"Please select what you want to buy:\n"
		"1. car($1000000)\n"
		"2. house($5000000)\n"
		"Choice: "
		);
	uint32_t op = read_int();
	uint32_t custom = 0;

	switch (op) {
		case 1: custom = 1000000; break;
		case 2:	custom = 5000000; break;
		default: return write_n("It is not available at present!\n\n");
	}

	if (player.money >= custom) {
		if (op == 1) {
			player.money -= custom;
			player.have_car = 1;
			return write_n("Congratulations, you have become a car owner, one step closer to a successful woman!\n\n");
		}
		else {
			player.money -= custom;
			player.have_house = 1;
			return write_n("Congratulations, you have become a homeowner. Now that you have a firm foothold in the big city, you are one step closer to a high-quality life!\n\n");
		}
	} 
	write_n("Sorry, right now your savings are not enough to buy it.So keep working hard, girl!\n\n");
}

uint32_t lying_flat() {
	return write_n("You lay flat all day and nothing happened!\n\n");
}

uint32_t get_married() {
	if (player.have_married) {
		return write_n("You're married! How could you betray your husband?\n\n");
	}

	write_n("Wow, this is an important moment in your life. Which male friends do you want to marry?");
	uint32_t idx = read_int();

	if (idx >= number || !male_friends[idx]) {
		return write_n("You don't even know him. How can you be so casual?\n\n");
	}

	write_n(
		"You and your boy: \n"
		"Father, Smith, Warrior, Mother, Maiden, Crone, Stranger:\n"
		"I'm hers(His) and she(he)'s mine,\n"
		"from this day until the end of my days.\n"
		);
	write_n("Having said the wedding vows, each now promises to the other for life!\n");
	player.have_married = 1;
	player.husband = male_friends[idx];

	write_n("Now, your groom will make a lifetime commitment to you: ");
	write_n((player.husband)->ptr);
	write_n("\n");

	write_n("Next, you will make a lifetime commitment to your groom: ");
	read_n((player.husband)->ptr, (player.husband)->score);

	write_n("Then, he's already your husband. It's time for a new nickname: ");
	read_n(player.husband, 0x10);

	return write_n("That's it. Congratulations on becoming husband and wife. May you live a long life together!\n\n");
}

uint32_t quality_life() {
	if (player.have_quality_life) {
		return write_n("Just one chance!\n\n");
	}

	if (player.have_car && player.have_house && player.money >= 10000000) {
		player.have_quality_life = 1;
		write_n(
			"Wow, you are a very successful lady now!\n"
			"It is said that women are strong and will not rely too much on others!\n"
			"In return, God has given you a chance to use your powers!\n"
			"Say in advance, the opportunity only once, regardless of use success or failure are calculated, so carefully use!\n"
			);
		write_n("Please choice a male friends: ");
		uint32_t idx = read_int();

		if (idx >= number || !male_friends[idx]) {
			return write_n("No No No! You're not friends with him!\n\n");
		}

		write_n("Put your thoughts in his heart: ");
		read_n(male_friends[idx]->ptr, male_friends[idx]->score);

		return write_n("Power use complete!\n\n");
	}
	else {
		return write_n("No No No! You are not yet a high quality human woman! Try hard!\n\n");
	}
}