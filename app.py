from flask import Flask, request,flash, url_for, session
from flask import render_template
from flask import redirect
from jinja2 import Markup
import boto3
from model import User
from boto3.dynamodb.conditions import Key
import uuid
import hashlib
from flask_moment import Moment
from datetime import datetime
from flask_bootstraps import Bootstrap




app = Flask(__name__)
bootstrap=Bootstrap(app)
app.config["SECRET_KEY"] = '1779'  # The secret key to open the cookie.
moment = Moment(app)
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

tableName = 'Users'



def create_table():

    table = dynamodb.create_table(
        TableName=tableName,
        KeySchema=[
            {
                'AttributeName': 'UserName',
                'KeyType': 'HASH'  #Partition key
            },
            {
                'AttributeName': 'TaskId',
                'KeyType': 'RANGE'  #Sort key
            }
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': "UserIndex",
                'KeySchema': [
                    {
                        'KeyType': 'HASH',
                        'AttributeName': 'UserName'
                    },
                    {
                        'KeyType': 'RANGE',
                        'AttributeName': 'TaskId'
                    }
                ],
                'Projection': {
                    'ProjectionType': 'INCLUDE',
                    'NonKeyAttributes': ['Password', 'Salt']
                },
                'ProvisionedThroughput' : {
                    'ReadCapacityUnits': 2,
                    'WriteCapacityUnits': 2
                }
            },
            {
                'IndexName': "DoneIndex",
                'KeySchema': [
                    {
                        'KeyType': 'HASH',
                        'AttributeName': 'UserName'
                    },
                    {
                        'KeyType': 'RANGE',
                        'AttributeName': 'TaskId'
                    }
                ],
                'Projection': {
                    'ProjectionType': 'INCLUDE',
                    'NonKeyAttributes': ['TaskContent', 'Done']
                },
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 2,
                    'WriteCapacityUnits': 2
                }
            },
        ],

        AttributeDefinitions=[
            {
                'AttributeName': 'UserName',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'TaskId',
                'AttributeType': 'N'
            },

        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10
        }
    )

    return

def insert_user_to_table(UserName, Password, Salt,TaskId):

    table = dynamodb.Table(tableName)

    response = table.put_item(
       Item={
            'UserName': UserName,
            'Password': Password,
            'Salt': Salt,
            'TaskId':TaskId
        }
    )
    return

def insert_task_to_db(UserName, TaskId, TaskContent, Done):
    table = dynamodb.Table(tableName)

    response = table.put_item(
        Item={
            'UserName': UserName,
            'TaskId': TaskId,
            'TaskContent':TaskContent,
            'Done': Done
        }
    )
    return

def  query_user_by_name(username):
    table = dynamodb.Table(tableName)

    response = table.query(
        IndexName='UserIndex',
        KeyConditionExpression=Key('UserName').eq(username)
    )
    records = []
    for i in response['Items']:
        records.append(i)
    if len(records) < 1:
        return None

    return records

def query_max_taskid(username):
    table = dynamodb.Table(tableName)
    response = table.query(
        IndexName='DoneIndex',
        KeyConditionExpression=Key('UserName').eq(username)
    )
    records = []
    for i in response['Items']:
        records.append(i['TaskId'])
    if len(records) < 1:
        return None
    return max(records)

def query_usertask_by_taskid(username, taskid):
    table = dynamodb.Table(tableName)
    response = table.query(
        IndexName='DoneIndex',
        KeyConditionExpression=Key('UserName').eq(username) & Key('TaskId').eq(taskid)
    )
    records = []
    for i in response['Items']:
        records.append(i)
    if len(records) < 1:
        return None
    return records

def delete_task_by_taskid(username, taskid):
    table = dynamodb.Table(tableName)
    response = table.delete_item(
        Key={'UserName': username,
             'TaskId':taskid
             }
    )
    return

def update_done_by_taskid(username, taskid, done):
    table = dynamodb.Table(tableName)
    response = table.update_item(
        Key={'UserName': username,
             'TaskId': taskid
             },
        UpdateExpression = "set Done = :d",
        ExpressionAttributeValues={
            ':d': done
        }
    )
    return



def hash(password, salt):
    salted_pwd = password + salt
    hashed_pwd = hashlib.sha256(salted_pwd.encode()).hexdigest()
    return hashed_pwd

#Greetints to users
from jinja2 import Markup


class momentjs:
    def __init__(self, timestamp):
        self.timestamp = timestamp

    def render(self, format):
        return Markup("<script>\ndocument.write(moment(\"%s\").%s);\n</script>" % (
        self.timestamp.strftime("%Y-%m-%dT%H:%M:%S Z"), format))

    def format(self, fmt):
        return self.render("format(\"%s\")" % fmt)

    def calendar(self):
        return self.render("calendar()")

    def fromNow(self):
        return self.render("fromNow()")

@app.route('/register/', methods=['GET', 'POST'])
def user_register():
    if request.method == "POST":
        user = User()
        user.name = request.form["username"]
        # To see if the user has already exists
        if len(user.name) > 100:
            flash("The length of username is illegal!", category='error')
            return render_template('register.html')
        user_x = query_user_by_name(user.name)
        if user_x:
            flash("The name already exists!", category='error')
            return render_template('register.html')
        if request.form["password_confirm"] != request.form["password"]:
            flash("Two passwords are inconsistent!", category='error')
            return render_template('register.html')
        salt = uuid.uuid4().hex
        user.salt = salt
        user.password = hash(request.form["password"], salt)
        # If this is a new user, operate insert operation
        user.taskid = 0
        insert_user_to_table(user.name, user.password, user.salt, user.taskid)
        flash("You have successfully registered!", category='ok')
        return redirect(url_for("user_login", username=user.name))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def user_login():
    #print(type(query_user_by_name('violet')))
    if 'username' in session:
        return redirect(url_for('user_visit', username=session["username"]))
    if request.method == "POST":
        username = request.form["username"]
        userpassword = request.form["password"]
        user_x = query_user_by_name(username)
        # examine if this username exists
        if not user_x:
            flash("The username does not exist. Please try again.", category='error')
            return render_template('login.html')
        else:
            print(user_x)
            user_x = user_x[0]
            print(user_x)
            new_key = hash(userpassword, user_x['Salt'])
            if new_key != user_x['Password']:
                #print(new_key)
                flash("Password error.", category='error')
                return render_template('login.html')
            else:
                session["username"] = username
                session['authenticated'] = True  # login status
                session['error'] = None
                return redirect(url_for('user_visit', username=session["username"]))
    return render_template('login.html')


@app.route('/user/<username>', methods=['GET', 'POST'])
def user_visit(username):
    table = dynamodb.Table(tableName)
    response = table.query(
        IndexName = 'DoneIndex',
        KeyConditionExpression= Key('UserName').eq(username)
    )
    records = []
    for i in response['Items']:
        if i['TaskId'] != 0:
            records.append(i)
    #print(records)
    return render_template("user_page.html", username=username, tasks=records, current_time=datetime.utcnow())


@app.route('/user/add_task', methods=['POST'])
def add_task():
    content = request.form['content']
    if not content:
        return 'Error'
    username = session['username']
    #print("1", query_usertask_by_name(username))
    maxid = query_max_taskid(username)
    #print("user_x", user_x)
    taskid = maxid + 1
    Done = False
    insert_task_to_db(username, taskid, content, Done)
    return redirect(url_for('user_visit', username=username))


@app.route('/user/delete/<int:task_id>')
def delete_task(task_id):
    username = session["username"]
    task = query_usertask_by_taskid(username, task_id)
    if not task:
        return redirect('/user/<username>')
    delete_task_by_taskid(username,task_id)
    return redirect(url_for('user_visit', username=username))


@app.route('/user/done/<int:task_id>')
def resolve_task(task_id):
    username = session["username"]
    task = query_usertask_by_taskid(username, task_id)[0]
    #print(task)
    if not task:
        return redirect('/user/<username>')
    if task['Done']:
        task['Done'] = False
    else:
        task['Done'] = True
    update_done_by_taskid(username, task_id, task['Done'])
    return redirect(url_for('user_visit', username=username))

@app.route('/logout')
def user_logout():
    session.pop("username", None)
    session.pop('authenticated', None)
    if 'error' in session:
        session['error'] = None
    return redirect(url_for('user_login'))



if __name__ == '__main__':
    app.run(debug=False)


