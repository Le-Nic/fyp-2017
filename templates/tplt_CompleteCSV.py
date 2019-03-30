import pandas as pd
from src import warehouse


extSupport = ['csv']

def genCSV(fileName):
	# TODO: column sorting, display enhancing
	for vuln in warehouse.vulnList:

		vulnStuffs = {
			'Scanner': vuln.scanner,
			'IP Address': vuln.ip,
			'Host Name': vuln.host,
			'Operating System': vuln.os
		}

		for key, val in vulnStuffs.items():
			if isinstance(val, list) is True:
				if val:
					vuln.data[key] = '\n'.join(filter(None, val))
				else:
					vuln.data[key] = None
			else:
				vuln.data[key] = val

		for index, row in vuln.data.iterrows():
			for column, aData in row.items():
				if column == 'refURL':
					if isinstance(aData, list):
						aData = [eachRef[5:] for eachRef in aData if eachRef.startswith('(URL)')]

				if isinstance(aData, list) is True:
					if aData:
						row[column] = '\n'.join(filter(None, aData))
					else:
						row[column] = None

	with open(fileName, 'w') as f:
		pd.concat([vuln.data for vuln in warehouse.vulnList], sort=True).to_csv(f)
	'''
	# csv support only 1 sheet
	for eachOut in fileName:
		print(eachOut)
		writer = ExcelWriter('test.xlsx')
		for n, vuln in enumerate(warehouse.vulnList):
			vuln.data.to_excel(writer,'sheet{}'.format(n))
		writer.save()
	'''
def compile(colr, outFile, merged):

	if outFile['extension'] == 'csv':
		genCSV(outFile['filename'])
