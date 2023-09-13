import os
from datetime import datetime

def getEnvironmentInfo():
	cwd = os.getcwd()
	user = os.environ.get('USER')
	home = os.path.expanduser('~')
	pg3init = os.getenv('PG3INIT') or "Not set"

	return {
		'cwd': cwd,
		'user': user,
		'home': home,
		'pg3init': pg3init
	}

def writeCrashInfo(error):
	info = getEnvironmentInfo()

	now = datetime.now()
	current_time = now.strftime("%H:%M:%S") + ' '

	f = open('{}/crash.log'.format(info.get('cwd')), "a")

	f.write(current_time + 'Node server started with this information:\n')
	f.write(current_time + ' User={}\n'.format(info.get('user')))
	f.write(current_time + ' Home={}\n'.format(info.get('home')))
	f.write(current_time + ' Node server path={}\n'.format(info.get('cwd')))
	f.write(current_time + ' PG3INIT={}\n'.format(info.get('pg3init')))
	f.write(current_time + ' Error message: {}\n'.format(error))

	f.close()