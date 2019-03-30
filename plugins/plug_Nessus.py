import lxml.etree as ET
from src import warehouse


colr = [0x4f, 0x81, 0xbd]

signature = {
	'root': 'NessusClientData_v2',
	'element': ['self::Policy','self::Report']
}

def extract(data):

	#print('\nCalling from Nessuss!\n')

	# "Report" section can contain zero or one report per .nessus file
	# https://static.tenable.com/documentation/nessus_v2_file_format.pdf
	context = ET.iterparse(data, events=('end',), tag='ReportHost')

	# parse by block of host
	for event, ReportHost in context:	# ReportHost

		hostIP = None
		hostOs = None
		hostName = ReportHost.get('name')

		for HostProperties in ReportHost.iterchildren(tag='HostProperties'):	# HostProperties

			for HPtag in HostProperties:	# HostProperties.tag

				if 'host-ip' in HPtag.get('name'):
					hostIP = HPtag.text
				elif 'operating-system' in HPtag.get('name') :
					hostOs = HPtag.text.split('\n')
				elif 'netbios-name' in HPtag.get('name'):
					hostName = HPtag.text

		dataStore = warehouse.vulnStore('Nessus', hostIP, hostName, hostOs, [	# initialize class object
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

		for ReportItem in ReportHost.iterchildren(tag='ReportItem'):	# ReportItem

			name = ReportItem.get('pluginName')
			if name:
				dataBuf = {
					'name': name,
					'port': [(ReportItem.get('port') + '/' + ReportItem.get('protocol'))] if ReportItem.get('port') != '0' else None,
					'severity': ReportItem.get('severity'),
					'risk': None,

					'summary': None,
					'description': None,
					'solution': None,

					'extra': None,
					'ref': [],
					'refURL': [],

					'cvss(b/v)': [],
					'cvss(ts/tv)': []
				}
			else:
				continue

			for elem in ReportItem.iterchildren((
				'name', 'port', 'protocol', 'severity',	# always & once
				'synopsis', 'description', 'solution',	# often & once
				'bid', 'cpe', 'cve', 'xref',	# often & more
				'risk_factor', 'see_also', 'plugin_output',	# often & once
				'cvss_base_score', 'cvss_temporal_score', 'cvss_temporal_vector', 'cvss_vector'	# seldom & once
			)):

				if 'synopsis' == elem.tag:
					dataBuf['summary'] = elem.text
				elif 'description' == elem.tag:
					dataBuf['description'] = elem.text
				elif 'solution' == elem.tag:
					if elem.text != 'n/a':
						dataBuf['solution'] = elem.text

				elif 'bid' == elem.tag:
					dataBuf['ref'].append('BID:' + elem.text)
				elif 'cpe' == elem.tag:
					dataBuf['ref'].append('CPE:' + elem.text)
				elif 'cve' == elem.tag:
					dataBuf['ref'].append('CVE:' + elem.text)
				elif 'xref' == elem.tag:
					dataBuf['ref'].append(elem.text)

				elif 'risk_factor' == elem.tag:
					if elem.text != 'None':
						dataBuf['risk'] = elem.text
				elif 'see_also' == elem.tag:
					dataBuf['refURL'].extend(['(URL)'+url for url in elem.text.split()])
				elif 'plugin_output' == elem.tag:
					dataBuf['extra'] = elem.text

				elif elem.tag in ('cvss_base_score', 'cvss_vector'):
					dataBuf['cvss(b/v)'].append(elem.text)
				elif elem.tag in ('cvss_temporal_score', 'cvss_temporal_vector'):
					dataBuf['cvss(ts/tv)'].append(elem.text)

				# -?in_the_news
				# -?exploit_available
				# -?exploitability_ease
				# -?exploited_by_nessus

				# -*see_also
				# -*attachment <name, type>
				# -?plugin_output
				# -?cm:compliance-info
				# -?cm:compliance-result (PASSED | FAILED)
				# -?cm:compliance-actual-value
				# -?cm:compliance-info

			dataStore.add(dataBuf)

		ReportHost.clear()

		while ReportHost.getprevious() is not None:
			del ReportHost.getparent()[0]

	del context
