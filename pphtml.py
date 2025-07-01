import sys
with open(sys.argv[1]) as f:
	data = f.read()
	data = data.replace('RET_VERSION', 'v4.0')
	data = data.replace('<title>Ret</title>', '<title>Ret ' + sys.argv[2] + '</title>')
	print(data)
