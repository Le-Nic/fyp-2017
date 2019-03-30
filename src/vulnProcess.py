import lxml.etree as ET
import difflib
from src import iLoader
from src import warehouse


### filter and obtain all proper signatures from plugins
def getSignatures(plugins):

	signatures = []
	for i, plugin in enumerate(plugins):

		try:
			loaded = iLoader.load(plugin)

			myDict = {}

			if 'signature' in dir(loaded):

				if 'root' in loaded.signature:
					if loaded.signature['root'] != '' and loaded.signature['root'] != None:

						myDict.update({'plugin':plugin})
						myDict.update({'root' : loaded.signature['root']})

						if 'element' in loaded.signature:	# add elements if exist
							temp = []

							for ele in loaded.signature['element']:

								if ele != '' and ele != None:
									temp.append(ele)
									#temp.append(ET.XPath(ele))
									#temp.append(ET.XPath(''.join(['following::',ele])))

							myDict.update({'element' : temp})

						signatures.append(myDict)

		except Exception as e:
			continue
			#print('[ERROR] occured in plugin -> {}\n\t> {}'.format(plugin['name']), e)	# DEBUG

	return signatures
''

# import and obtain signature fields from each plugin to determine the type of imported file
def isReport(data, plugins):

	signatures = getSignatures(plugins)
	### get plugins which their root matches the document's
	try:
		sigI = []	# store indexes of detected signatures

		context = ET.iterparse(data, events=('start',))

		for event, elem in context:
			for i, sig in enumerate(signatures):

				if elem.tag == sig['root']:
					sigI.append(i)
			break

		del context
	except Exception as e:
		return None
		#print('[ERROR] occured when parsing the document -> {}\n\t> {}'.format(data, e))	# DEBUG

	### additional verification on the nodes using XPath
	if sigI is not None:

		for i in sigI:	# in case root is contained in more than one plugins

			if 'element' not in signatures[i]:
				return signatures[i]['plugin']

			else:

				try:
					signatures[i]['element'] = [ET.XPath(el) for el in signatures[i]['element']]	# XPath objects
					passCond = len(signatures[i]['element'])	# no. of conditions needed to pass

					context = ET.iterparse(data, events=('start',))

					for event, elem in context:

						for el in signatures[i]['element'][:]:	# create copy for removing

							if el(elem):
								passCond -= 1
								signatures[i]['element'].remove(el)
								#print('matched:',elem)	# DEBUG

						if passCond <= 0:	# fulfilled
							return signatures[i]['plugin']

						'''
						Inspired by Liza Daly (IBM)
						'''

						#elem.clear()

						while elem.getprevious() is not None:
							del elem.getparent()[0]

					del context
				except Exception as e:
					return None
					#print('[ERROR] occured when parsing the document -> {}\n\t> {}'.format(data, e))	# DEBUG

	else:
		return None


def extract(data, plugin):

	try:
		loaded = iLoader.load(plugin)

		if 'extract' in dir(loaded):	# KeyError
			loaded.extract(data)

		if 'colr' in dir(loaded):
			return loaded.colr
		else:
			return [0x00, 0x00, 0x00]

	except Exception as e:
		return e

def experimentalMerge():

	### PORTS MERGING STARTS HERE ###
	iterIndex = {}
	for vuln in warehouse.vulnList:
		iterIndex.update({vuln: []})

		lastName = ''
		iCluster = []
		for index, row in vuln.data[vuln.data.duplicated(['name'], keep = False)].sort_values(ascending=True, by='name').iterrows():

			if row['name'] != lastName:
				lastName = row['name']

				if iCluster:
					iterIndex[vuln].append(iCluster)
					iCluster = []
			iCluster.append(index)

		if iCluster:	# last cluster
			iterIndex[vuln].append(iCluster)

	for df, jClusters in iterIndex.items():
		for indexes in jClusters:
			index1 = indexes[0]

			for index2 in indexes[1:]:

				if df.data['port'][index1] != df.data['port'][index2]:
					sM = {'description': None} # plugin outputs?

					for key, val in sM.items():
						sM[key] = difflib.SequenceMatcher(lambda x: x == ' ',
							df.data[key][index1],
							df.data[key][index2])

					if sM['description'] is not None:
						if sM['description'].quick_ratio() > 0.98: # allow if similarity of description strings is over 98%
							df.data['port'][index1].extend(df.data['port'][index2])

							for key, val in sM.items():
								# attach/"merge" different strings in descriptions etc.

								if sM[key].quick_ratio() < 1.0:
									d = difflib.Differ()
									result = list(d.compare(df.data[key][index1].splitlines(1), df.data[key][index2].splitlines(1)))

									stringList = [line[2:] for line in result if line.startswith(('-', '+'))]
									newString = df.data[key][index1].splitlines(1)

									for i, strMatch in enumerate(stringList):
										for j, str in enumerate(newString):
											if strMatch == str:
												newString[j] += stringList[i-1]
												df.data[key][index1] = ''.join(newString)
												break

						df.data = df.data.drop([index2])
		df.data = df.data.reset_index(drop=True)
	### PORTS MERGING ENDS HERE ###

	### CVEs MERGING STARTS HERE ###
	'''
	#ip, host, os, scanner

	vulnTable: {
		ip: {
			scanner: {
				index: {
					'processed': False,
					'cves': [cveID]
				},
				index: {
					'processed': False,
					'cves': [cveID]
				},
			},
		},
	}

	cveTable: {
		cveID: {
			scanner: [index]
		},
	}

	linkedVuln: {
		ip: {
			num: {
				scanner:{
					index: [cveID],
				},
			},
		},
	}
	'''

	linkedVuln = {}
	vulnTable = {}
	cveTable = {}

	for vuln in warehouse.vulnList:
		for index, row in vuln.data.iterrows():

			cveID = []
			if row['ref']:
				for ref in row['ref']:

					if 'CVE' in ref[:3:]:
						aCVE = ref[4::]
						cveID.append(aCVE)

						# add cve to cveTable
						# different cve
						if aCVE not in cveTable:
							cveTable.update({
								aCVE: {
									vuln: [index]
								}
							})
						else:
							# different scanner
							if vuln not in cveTable[aCVE]:
								cveTable[aCVE].update({
									vuln: [index]
								})
							else:
								cveTable[aCVE][vuln].append(index)
			# add cveID to vulnTable if found
			if cveID:
				# new ip
				if vuln.ip not in vulnTable:
					vulnTable.update({
						vuln.ip: {
							vuln: {
								index: {
									'processed': False,
									'cves': cveID
					}}}})

				else:
					# new scanner
					if vuln not in vulnTable[vuln.ip]:
						vulnTable[vuln.ip].update({
							vuln: {
								index: {
									'processed': False,
									'cves': cveID
								}
							}
						})
					else:
						# new vulnerability
						vulnTable[vuln.ip][vuln].update({
							index: {
								'processed': False,
								'cves': cveID
							}
						})

	for vuln_ip, vuln_dfs in vulnTable.items():
		dictCount = 0
		for vuln_df, vuln_indexes in vuln_dfs.items():
			for vuln_index, vuln_info in vuln_indexes.items():
				if vuln_info['processed'] is False:

					ptr = 0
					linkedCVEs = vuln_info['cves']
					count = 0

					while ptr < len(linkedCVEs):
						for cve_df, cve_indexes in cveTable[linkedCVEs[ptr]].items():
							if cve_df.ip == vuln_ip:
								for cve_index in cve_indexes:
									if vulnTable[vuln_ip][cve_df][cve_index]['processed'] is False:
										vulnTable[vuln_ip][cve_df][cve_index]['processed'] = True

										for vuln_cve in vulnTable[vuln_ip][cve_df][cve_index]['cves']:
											if vuln_cve not in linkedCVEs:
												linkedCVEs.append(vuln_cve)

										if vuln_ip not in linkedVuln:
											linkedVuln.update({
												vuln_ip: {
													dictCount: {
														cve_df: {
															cve_index: vulnTable[vuln_ip][cve_df][cve_index]['cves']
														}
													}
												}
											})
										else:
											if dictCount not in linkedVuln[vuln_ip]:
												linkedVuln[vuln_ip].update({
													dictCount: {
														cve_df: {
															cve_index: vulnTable[vuln_ip][cve_df][cve_index]['cves']
														}
													}
												})
											else:
												if cve_df not in linkedVuln[vuln_ip][dictCount]:
													linkedVuln[vuln_ip][dictCount].update({
														cve_df: {
															cve_index: vulnTable[vuln_ip][cve_df][cve_index]['cves']
														}
													})
												else:
													linkedVuln[vuln_ip][dictCount][cve_df].update({
														cve_index: vulnTable[vuln_ip][cve_df][cve_index]['cves']
													})
										count += 1
						ptr += 1
					# delete not merged
					if count == 1:
						del linkedVuln[vuln_ip][dictCount]
					else:
						dictCount += 1

	### CVE MERGING ENDS HERE ###

	return linkedVuln



def compile(colr, outFile, template, merged):

	try:
		loaded = iLoader.load(template)

		if 'compile' in dir(loaded):
			loaded.compile(colr, outFile, merged)
			return False
		else:
			return 'Function compile not found in selected template'
	except Exception as e:
		return e
