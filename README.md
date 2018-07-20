# Rose Back End

### Rose Back End is a Python Flask API for authenticating and managing users 

#### installation and use on linux

1. clone the repo
```
git clone https://github.com/jwpowers2/rose_back_end
```
2. install pip if you don't have it using apt-get or yum
```
apt-get install python-pip
```
3. install the dependencies using pip
```
pip install -r requirements.txt
```
4. start flask server
```
flask run
```
5. You'll also need postgres installed, and you'll to set up a user for the DB with users in it

### User Story

#### Registration

1. User registers: sends email, password, confirm_password to Rose Back End (RBA)

2. RBA filters user input and if it is ok, saves the user in the Postgres DB 

3. RBA then makes a JSON Web Token and send it back to the client

#### Login

1. User logs in again, sends email and password to RBA

2. RBA authenticates parameters against DB data 

3. if successful, RBA sends JWT back to client


#### Limiting Access 

1. User wants to use a restricted page

2. The restricted page looks for JWT in localStorage and if it finds it, send to RBA

3. RBA authenticates and send back True, if so

#### Limiting Access to functionality

1. User is on a restricted page and wants to see users

2. An API call to restricted methods in RBA is always accompanied by a JWT

3. The JWT is authenticated and if it fails, the user cannot fire the restricted method

4. restricted functionality includes getting user data and deleting users
