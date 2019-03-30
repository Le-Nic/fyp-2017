import lxml.etree as ET
from src import warehouse


colr = [0x70, 0xad, 0x47]

signature = {
	'root': 'report',
	'element': ["", 'self::report/report/results'] #descendant::report_format/name[contains(text(), 'XML')]
}

# TODO: same vulnerability on different ports, difference in description (https and http)
def extract(data):

	#print('\nCalling from OpenVAS!\n')

	context = ET.iterparse(data, events=('end',), tag='results')

	for event, results in context:	# report/report/results

		hostIP = {}	# store IP and class address

		for result in results.iterchildren('result'):	# result
			breakNow = False
			currentHost = None

			dataBuf = {
				'name': None,
				'port': [],
				'severity': None,
				'risk': None,

				'summary': None,
				'description': None,
				'impact': None,
				'solution': None,

				'extra': None,
				'ref': [],
				'refURL': [],

				'cvss(b/v)': []
			}

			for elem in result.iterchildren((
				'host', 'port',
				'nvt',
				'description', 'threat', 'severity'
			)):

				if 'host' == elem.tag:
					currentHost = elem.text	# to classify which IP the vulnerability belongs to

					if elem.text not in hostIP:	# encountered a new IP
						hostIP.update({elem.text:
							warehouse.vulnStore('OpenVAS', elem.text, None, None, [	# initialize class object
								'name',
								'port',
								'severity',
								'summary',
								'description',
								'solution',
								'extra',
								'ref',
								'refURL',
								'cvss(b/v)'
							])
						})

				if 'port' == elem.tag:
					dataBuf['port'].append(elem.text)

				elif 'nvt' == elem.tag:
					for ele in elem.iterchildren((
						'name', 'cvss_base', 'cve', 'bid',
						'tags',
						'cert',
						'xref'
					)):
						if 'name' == ele.tag:
							if ele.text:
								dataBuf['name'] = ele.text
							else:
								breakNow = True

						elif 'cvss_base' == ele.tag:
							dataBuf['cvss(b/v)'].append(ele.text)

						elif 'cve' == ele.tag:
							if ele.text != 'NOCVE':
								dataBuf['ref'].extend(['CVE:'+x for x in ele.text.split(', ')])

						elif 'bid' == ele.tag:
							if ele.text != 'NOBID':
								dataBuf['ref'].extend(['BID:'+x for x in ele.text.split(', ')])

						elif 'tags' == ele.tag:
							tagElements = ele.text.replace('=', '|').split('|')

							for head, body in zip(tagElements[0::2], tagElements[1::2]):
								if 'cvss_base_vector' == head:
									dataBuf['cvss(b/v)'].append(body)
								elif 'impact' == head:
									if dataBuf['impact'] is not None:
										dataBuf['impact'] = body + dataBuf['impact']
									else:
										dataBuf['impact'] = dataBuf['impact']
								elif 'vuldetect' == head:	# detection method
									dataBuf['extra'] = body
								elif 'insight' == head:
									if dataBuf['description'] is not None:
										dataBuf['description'] += '\n\nInsight:\n{}'.format(body)
									else:
										dataBuf['description'] = 'Insight:\n{}\n'.format(body)
								elif 'solution' == head:
									dataBuf['solution'] = body
								elif 'summary' == head:
									dataBuf['summary'] = body
								elif 'affected' == head:
									if dataBuf['impact'] is not None:
										dataBuf['impact'] += '\n\nAffected Software/OS:\n{}\n'.format(body)
									else:
										dataBuf['impact'] = 'Affected Software/OS:\n{}\n'.format(body)

						elif 'cert' == ele.tag:
							for cert in ele.iterchildren():
								dataBuf['ref'].append(cert.get('type') + ':' + cert.get('id'))

						elif 'xref' == ele.tag:
							if ele.text != 'NOXREF':

								for xref in ele.text.split(', '):
									ref = xref.split(':', maxsplit=1)

									if ref[0] == 'URL':
										dataBuf['refURL'].append('(URL)' + ref[1])
									else:
										dataBuf['ref'].append(ref[0] + ':' + ref[1])

				elif 'description' == elem.tag:
					if elem.text is not None:
						splat = elem.text.split('Solution:')

						if splat[0] != '':
							if dataBuf['description'] is not None:
								dataBuf['description'] = splat[0] + '\n\n' + dataBuf['description']
							else:
								dataBuf['description'] = splat[0]

						if len(splat) > 1:
							if dataBuf['solution'] is not None:
								dataBuf['solution'] += '\n\n' + splat[1]
							else:
								dataBuf['solution'] = splat[1]

				elif 'threat' == elem.tag:
					if elem.text != 'Log':
						dataBuf['risk'] = elem.text

				elif 'severity' == elem.tag:
					dataBuf['severity'] = elem.text.rstrip('0').rstrip('.') if '.' in elem.text else elem.text

			if breakNow:
				continue

			df = hostIP[currentHost].data
			dupIndex = df.name[df.name == dataBuf['name']].index.tolist()
			duplicate = False

			for index in dupIndex:
				# remove vulnerability with only a different port
				if 	df.description[index] == dataBuf['description'] and df.solution[index] == dataBuf['solution'] and df.ref[index] == dataBuf['ref'] and df.port[index] != dataBuf['port']:
					df.port[index].extend(dataBuf['port'])
					duplicate = True
					break

			if not duplicate:
				hostIP[currentHost].add(dataBuf)

			result.clear()

			while result.getprevious() is not None:
				del result.getparent()[0]

#REPORT STRUCTURE
'''
	report
		report
			ports
				port
			results
				result
					host	-> ip
					port	-> port
					nvt
						name	-> name
						cvss_base	-> cvss(b/v)
						<cve>	-> ref
						<bid>	-> ref
						tags
							cvss_base_vector	-> cvss(b/v)
							solution	-> solution
							summary		-> summary
							?impact	-> impact
							?vuldetect	-> extra
							?insight	-> insight
							?affected	-> affected
							?qod_type
							?solution_type
						<cert/>
							cert_ref -> ref (attr: id type)
						<xref>	URL -> refURL	Others -> ref
					<description/>	-> description
					?threat	-> risk(chars)
					?severity	-> severity(int)
					?original_threat
					?original_severity
'''
