import os, boto3, collections
# Statement for enabling the development environment
DEBUG = True

# Define the application directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))  
SAML_PATH = f'{BASE_DIR}/app/saml'
# Define the database - we are working with
# SQLite for this example
#SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
#DATABASE_CONNECT_OPTIONS = {}

# Application threads. A common general assumption is
# using 2 per available processor cores - to handle
# incoming requests using one and performing background
# operations using the other.
THREADS_PER_PAGE = 2

# Enable protection agains *Cross-site Request Forgery (CSRF)*
CSRF_ENABLED     = True

# Use a secure, unique and absolutely secret key for
# signing the data. 
CSRF_SESSION_KEY = "secret"

# Secret key for signing cookies
SECRET_KEY = "THISISASUPERBIGSECRET"

SESSION_COOKIE_DOMAIN="YOUR_DOMAIN_HERE"
SESSION_DYNAMODB_TABLE=os.environ["SESSION_TABLE"]
SLACK_MAPPING_TABLE=os.environ["SLACK_TABLE"]

REGION = 'us-west-2' if "AWS_REGION" not in os.environ else os.environ["AWS_REGION"]
AWS_REGION = REGION
SESSION_DYNAMODB_REGION = REGION

BLOCK_URL = "https://slack.com/api/chat.postMessage"
DEV_OPS_CHANNEL = "YOUR_CHANNEL_HERE"

#Set up our boto clients
DYNAMODB = boto3.resource('dynamodb', region_name=REGION)
SSM = boto3.client('ssm', region_name=REGION)

#Get our Slack Auth Token from SSM
SLACK_OAUTH="SLACK_AUTH_TOKEN_HERE"