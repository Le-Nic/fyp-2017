import imp
import os


# return list of plugins in dir
def getPlugs(iDir):
	plugins = []
	allPlugins = os.listdir(iDir)

	for i in allPlugins:
		if not os.path.isdir(i) and i.startswith('plug_') and i.endswith('.py'): # not dir, and fulfill "plug_xxx.py" naming convention
			info = imp.find_module(i[:-3], [iDir])
			name = i[:-3].replace('plug_', '', 1).split('_')

			if len(name) == 2:
				plugins.append({
					'name': name[0],
					'type': name[1],
					'info': info
				})
			else:
				plugins.append({
					'name': name[0],
					'type': 'default',
					'info': info
				})

	return plugins

def getTplts(iDir):
	templates = []
	allTemplates = os.listdir(iDir)

	for i in allTemplates:
		if not os.path.isdir(i) and i.startswith('tplt_') and i.endswith('.py'): # not dir, and fulfill "tplt_xxx.py" naming convention
			info = imp.find_module(i[:-3], [iDir])

			templates.append({
				'name': i[:-3].replace('tplt_', '', 1),
				'info': info
			})

	return templates

#load and use plugin
def load(plugin):
	return imp.load_module(plugin['name'], *plugin['info'])
