import lxml.etree as ET
from src import warehouse


colr = [0xf7, 0x96, 0x46]

signature = {
	'root': 'NexposeReport',
	'element': ['descendant::nodes/node', 'self::VulnerabilityDefinitions'] #descendant::report_format/name[contains(text(), 'XML')]
}

def extract(data):

	#print('\nCalling from Nexpose!\n')

	vulnLinks = {}
	hostLinks = {}

	context = ET.iterparse(data, events=('end',), tag='node')
	context2 = ET.iterparse(data, events=('end',), tag='vulnerability')

	for event, node in context:	# NexposeReport/nodes/node

		hostIP = node.get('address')
		hostName = None
		os = []
		ports = []	# open ports (incd. opened ports w/o vulnerabilities)

		for elems in node.iterchildren((
			'names', 'fingerprints',
			'tests', 'endpoints'
		)):

			if elems.tag == 'names':	# get only first occurence
				hostName = elems[0].text

			elif elems.tag == 'fingerprints':	# get all possible OSs
				os.extend([' '.join(filter(None, [elemOs.get('product'), elemOs.get('version'), elemOs.get('arch')])) for elemOs in elems.iterchildren()])

			elif elems.tag == 'tests':

				for test in elems.iterchildren():
					vulnID = test.get('id')

					if vulnID in vulnLinks:

						if hostIP in vulnLinks[vulnID]:	# create {'0': pci} when same IP exists
							vulnLinks[vulnID][hostIP]['port'].append('0')

							vulnLinks[vulnID][hostIP].update({
								'PCI': test.get('pci-compliance-status')
							})

						else:	# create {IP: {'0': pci}} when it's different IP
							vulnLinks[vulnID].update({
								hostIP: {
									'port': ['0'],
									'PCI': test.get('pci-compliance-status')
								}
							})

					else:	# create {vulnID: {IP: {'0': pci}}} when ID not exists
						vulnLinks.update({
							vulnID: {
								hostIP: {
									'port': ['0'],
									'PCI': test.get('pci-compliance-status')
								}
							}
						})


			elif elems.tag == 'endpoints':
				for endpoint in elems.iterchildren():	# .../endpoints/endpoint
					port = endpoint.get('port') + '/' + endpoint.get('protocol')
					ports.append(port)

					for tests in endpoint[0][0].iterchildren('tests'):	# .../services/service/tests
						for test in tests.iterchildren():	# .../test
							vulnID = test.get('id')

							if vulnID in vulnLinks:

								if hostIP in vulnLinks[vulnID]:
									vulnLinks[vulnID][hostIP]['port'].append(port)

									vulnLinks[vulnID][hostIP].update({
										'PCI': test.get('pci-compliance-status')
									})

								else:
									vulnLinks[vulnID].update({
										hostIP: {
											'port': [port],
											'PCI': test.get('pci-compliance-status')
										}
									})
							else:
								vulnLinks.update( {
									vulnID: {
										hostIP: {
											'port': [port],
											'PCI': test.get('pci-compliance-status')
										}
									}
								})

		hostLinks.update({
			hostIP: {
				'port': ports,
				'store': warehouse.vulnStore('Nexpose', hostIP, hostName, os, [	# initialize class object
					'name',
					'port',
					'solution',
					'severity',
					'ref',
					'refURL',
					'cvss(b/v)'
				])
			}
		})

		node.clear()

		while node.getprevious() is not None:
			del node.getparent()[0]

	# LINKS' STRUCTURE
	'''
	vulnLinks = {
		vulnerable ID : {
			hostIP : {
				'port': port
				'PCI': pci
			},
		},
	}
	hostLinks = {
		hostIP: {
			'port': ports
			'store': warehouse.vulnStore
		},
	}
	'''

	for event, vulnerability in context2:	# NexposeReport/VulnerabilityDefinitions/vulnerability

		dataBuf = {
			'name': None,
			'port': [],

			'description': None,
			'solution': None,

			'PCI': [],
			'severity': None,

			'ref': [],
			'refURL': [],
			'tag': [],

			'cvss(b/v)': []
		}
		vulnID = vulnerability.get('id')

		dataBuf['name'] =  vulnerability.get('title')
		if not dataBuf['name']:
			continue

		dataBuf['severity'] =  vulnerability.get('severity')
		dataBuf['PCI'].append(vulnerability.get('pciSeverity'))
		dataBuf['cvss(b/v)'] =  [vulnerability.get('cvssScore'), vulnerability.get('cvssVector')[1:-1]]

		for elems in vulnerability.iterchildren((
			'malware', 'exploits', 'description', 'references', 'tags', 'solution'
		)):
			if elems.tag == 'exploits':

				for exploit in elems.iterchildren():	# exploit format: 'type': 'title' (url)'url'
					dataBuf['refURL'].append('{}: {} (URL){}'.format(exploit.get('type'), exploit.get('title'), exploit.get('link')))

			elif elems.tag == 'description':
				tempDesc = ''
				for desc in elems.iter():	# ContainerBlockElement
					tempDesc += ' ' + desc.text.strip()
					if desc.tag == 'URLLink':
						tempDesc += '({})'.format(desc.get('LinkURL'))

				if tempDesc:
					dataBuf['description'] = tempDesc

			elif elems.tag == 'references':

				for reference in elems.iterchildren():
					source = reference.get('source')

					if source == 'URL':
						dataBuf['refURL'].append('(URL)' + reference.text)
					else:
						if source == 'CERT-VN':
							source = 'CERT'
						dataBuf['ref'].append('{}:{}'.format(source, reference.text))

			elif elems.tag == 'tags':

				for tag in elems.iterchildren():
					dataBuf['tag'].append(tag.text)

			elif elems.tag == 'solution':
				tempSol = []

				for sol in elems[0].iter():	# ContainerBlockElement

					if sol.text and sol.text.strip() != '':
						tempSol.append(sol.text.strip())	# strip more \n ?
					if sol.tag == 'URLLink':
						tempSol.append(sol.get('LinkURL'))

				dataBuf['solution'] = '\n'.join(tempSol)

		for ip in vulnLinks[vulnID]:
			dataBuf['port'].extend(vulnLinks[vulnID][ip]['port'])

			if len(dataBuf['port']) == 1 and dataBuf['port'][0] == '0':
				dataBuf['port'] = None

			dataBuf['PCI'].append(vulnLinks[vulnID][ip]['PCI'])
			hostLinks[ip]['store'].add(dataBuf)







#REPORT's STRUCTURE
'''
1	exactly 1
!	0 or 1
?	0 or more
+	1 or more

	1NexposeReport
		1nodes
			+node	(attr: address)	-> IP
				!names
					+name	-> hostname
				!fingerprints
					+os	(attr: certainty vendor family product, optional: device-class version arch)	-> os
				1tests
					?test	(attr: id)	PERFORM LINKINGS
				!endpoints
					+endpoint	(attr: protocol port status)	-> port protocol
						1services
							1service
								1tests
									?test	(attr: id)	PERFORM LINKINGS

		1VulnerabilityDefinitions
			+vulnerability	(attr: id) PERFORM LINKINGS	(attr: title severity pciSeverity cvssScore cvssVector riskScore)	-> name pciseverity severity cvss(b/v) riskScore?
				!malware
				!exploits
					?exploit	(attr: title type link)	-> refURL
				1description	-> description
					1ContainerBlockElement
						<html>
						?ContainerBlockElement
						?Paragraph
						?OrderedList
							?ListItem
						?UnorderedList
						?URLLink	(attr: LinkURL)
						?Table
				1references
					?reference (attr: source="URL" and others)	-> refs refURL
				1tags
					?tag	-> tags
				1solution	-> solution
					1ContainerBlockElement
						<html>
'''
'''
	      <xsd:sequence minOccurs="0" maxOccurs="unbounded">
         <xsd:element name="ContainerBlockElement" type="ContainerBlockElementType" minOccurs="0" maxOccurs="unbounded"/>
         <xsd:element name="Paragraph" type="ParagraphType" minOccurs="0" maxOccurs="unbounded"/>
         <xsd:element name="OrderedList" type="OrderedListType" minOccurs="0" maxOccurs="unbounded"/>
         <xsd:element name="UnorderedList" type="UnorderedListType" minOccurs="0" maxOccurs="unbounded"/>
         <xsd:element name="URLLink" type="URLLinkType" minOccurs="0" maxOccurs="unbounded"/>
         <xsd:element name="Table" type="TableType" minOccurs="0" maxOccurs="unbounded"/>
      </xsd:sequence>
	  '''
