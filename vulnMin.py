#!/usr/bin/env python

__author__ = "Nicholas Lee"
__email__ = "lmz.nicholas@gmail.com"

import os
import sys
import argparse
import pathlib
import shutil
import filecmp
from tkinter import *
from tkinter.filedialog import askopenfilenames

from src import vulnProcess
from src import iLoader	# for handling installed plugins
from src import warehouse


plugins = iLoader.getPlugs('./plugins')
templates = iLoader.getTplts('./templates')


class Application(Frame):
	def __init__(self, master=None):
		super().__init__(master)

		self.pack(fill = BOTH, expand = True)
		self.create_widgets()
		self.filenames = ''

	def open(self):
		self.filenames = askopenfilenames()
		self.textbox1.insert(0, self.filenames)


	def ex3c(self):
		args.inExec = self.textbox1.get().split()
		GUI_tplt = [templates[self.rbVar.get()]['name']]
		GUI_merge = self.mergeVar1.get()
		GUI_output = [self.textbox2.get()]
		main(GUI_merge, GUI_tplt, GUI_output)	# template, output, merge

	def create_widgets(self):

		# FRAME 1
		self.frame1 = Frame(self)
		self.frame1.pack(fill = X)

		# ----- INPUT TEXTBOX -----
		self.label1 = Label(self.frame1, text = 'Report Files', anchor = W, padx = 16, pady = 5, width = 10)
		self.label1.pack(side = LEFT)
		self.textbox1 = Entry(self.frame1)
		self.textbox1.pack(side = LEFT, fill = X, expand = TRUE, anchor = W)

		# ----- BROWSE B. -----
		self.browse = Button(self.frame1, text="Browse", command = self.open)
		self.browse.pack(side = RIGHT, fill = X, padx = 10, pady = 5)

		# FRAME 2
		self.frame2 = Frame(self)
		self.frame2.pack(fill = X)

		# ----- OUTPUT TEXTBOX -----
		self.label2 = Label(self.frame2, text = 'Output Name', anchor = W, padx = 10, pady = 5, width = 10)
		self.label2.pack(side = LEFT)
		self.textbox2 = Entry(self.frame2)
		self.textbox2.pack(side = LEFT, padx = 11)

		# ----- MERGE CHECKBOX -----
		self.mergeVar1 = IntVar()
		self.merge = Checkbutton(self.frame2, text = 'Merge', variable = self.mergeVar1, onvalue = 1, offvalue = 0)
		self.merge.pack(side = LEFT)

		# FRAME 3
		self.frame3 = Frame(self)
		self.frame3.pack(fill = X, expand = TRUE, anchor = E, side = BOTTOM)

		# ----- EXECUTE B. -----
		self.execute = Button(self.frame3, text="Execute", command = self.ex3c)
		self.execute.pack(side = RIGHT, anchor = E, fill = X, padx = 10, pady = 10)

		# FRAME 4
		self.frame4 = Frame(self)
		self.frame4.pack(fill = Y, expand = TRUE, side = RIGHT, anchor = W, padx = 10, pady = 15)

		# ----- TEMPLATES R.B. -----
		self.label4 = Label(self.frame4, text = 'Templates', anchor = W)
		self.label4.pack(side = TOP, anchor = W)

		self.rbVar = IntVar()
		for i, tplt in enumerate(templates):

			self.tpltRB = Radiobutton(
				self.frame4,
				text = tplt['name'],
				variable = self.rbVar,
				value = i
			)
			self.tpltRB.pack(anchor = W)

# class for displaying help message on error
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('[ERROR] %s\n' % message)
        sys.stderr.write('\tinput -h or --help for proper usage and arguments help.\n')
        #self.print_help()
        sys.exit(2)

def execut3(reportss, selectedExt):

	# remove dup
	reports = []
	for rep in reportss:
		if rep not in reports:
			reports.append(rep)

	colr = {}

	i = 0
	# EXECUTE
	while i < len(reports):
		p = pathlib.Path(reports[i])

		try:
			if p.is_file():	# check if specified path is a file
				detectedPlugin = vulnProcess.isReport(reports[i], plugins)

				if detectedPlugin is not None:

					print('>> {} is assigned to.. '.format(p.name), end='')
					print('{} plugin ({})'.format(detectedPlugin['name'], detectedPlugin['type']))
					print('\t> Extracting.. ', end='')

					result = vulnProcess.extract(reports[i], detectedPlugin)

					if type(result) == list:
						print('SUCCEED'.rjust(shutil.get_terminal_size((80, 20)).columns-24))

						if detectedPlugin['name'] not in colr:
							colr.update({detectedPlugin['name']: result})
					else:
						print('FAILED'.rjust(shutil.get_terminal_size((80, 20)).columns-24))
						print('\t> {}'.format(result))
				else:
					raise
					None
			elif p.is_dir():	# check if specified path is a directory
				for child in p.iterdir():

					if pathlib.Path(child).is_file:
						reports.append(str(child))

			else:
				raise FileNotFoundError
				None
		except FileNotFoundError:
			print('[ERROR] File not found ->', reports[i])

		except Exception as e:
			print('[ERROR] Unsupported file type -> {}\n\t> {}'.format(reports[i], e))

		i += 1

	if len(warehouse.vulnList):

		merged = None
		# MERGE
		if args.mergeON:
			print('>> Consolidating data..', end='')
			merged = vulnProcess.experimentalMerge()
			if merged:
				print('SUCCEED'.rjust(shutil.get_terminal_size((80, 20)).columns-24))
			else:
				print('FAILED'.rjust(shutil.get_terminal_size((80, 20)).columns-24))

		# GENERATE
		for template in templates:

			if selectedExt['template'] == template['name']:
				print('>> Generating report.. ', end='')

				genError = vulnProcess.compile(colr, selectedExt, template, merged)

				if genError is False:
					print('SUCCEED'.rjust(shutil.get_terminal_size((80, 20)).columns-24))
					print('\t> Report {} is created'.format(selectedExt['filename']))
				else:
					print('FAILED'.rjust(shutil.get_terminal_size((80, 20)).columns-24))

					if genError:
						print ('\t> {}'.format(genError))
	else:
		print('>> Requirements not fulfilled, program terminated')

def main(GUI_merge=None, GUI_tplt=None, GUI_output=None):
	#----------PARAMETERS HANDLING STARTS HERE----------

	extensions = {}
	selectedExt = {
		'extension': None,
		'filename': None,
		'template': None
	}

	if GUI_merge is not None:
		if GUI_merge == 1:
			args.mergeON = True
		else:
			args.mergeOn = False

	if GUI_tplt is not None:
		args.inTplt = GUI_tplt

	if GUI_output is not None:
		args.inOut = GUI_output
		if type(GUI_output) == list:
			if GUI_output[0] == '':
				args.inOut = None

	# load supported file extensions for each template {name: [exts.]}
	for template in templates:
		try:
			loaded = iLoader.load(template)

			if 'extSupport' in dir(loaded):
				extensions.update({template['name']: loaded.extSupport})
		except:
			continue

	# INFORMATION
	if args.inInfo is not None:

		for inf in args.inInfo:
			if inf == 'plugins':
				print(
			'\nFound plugin(s):\n'\
			'---------------')

				for i, plugin in enumerate(plugins):
					print('\t{} {} ({})'.format(i+1, plugin['name'], plugin['type']))

			if inf == 'templates':
				print(
			'\nFound template(s):\n'\
			'-----------------')

				for i, template in enumerate(extensions):
					print('\t{} {} (available format: {})'.format(i+1, template, ', '.join(extensions[template])))
		exit()

	# EXECUTION
	if args.inExec is not None:

		if args.inTplt:	# specified TEMPLATE

			if args.inTplt[0] not in extensions:	# input validation
				parser.error('Specified template not found -> {}'.format(args.inTplt[0]))

			else:
				selectedExt['template'] = args.inTplt[0]
				print('>> Template {} is selected'.format(args.inTplt[0]))

				if args.inOut:	# specified TEMPLATE and OUTPUT
					ext = os.path.splitext(args.inOut[0])[1][1:]
					selectedTplt = selectedExt['template']

					if not ext:	# no extension specified
						selectedExt['extension'] = extensions[selectedTplt][0]
						selectedExt['filename'] = args.inOut[0] + '.' + selectedExt['extension']	# add supported extension to output file name
						print('>> No extension is specified')

					else:
						if ext not in extensions[selectedTplt]:	# validate supported extension
							selectedExt['extension'] = extensions[selectedTplt][0]
							selectedExt['filename'] = args.inOut[0][:-len(ext)] + selectedExt['extension']	# change to a supported extension
							print('>> Unsupported extension is specified')

						else:
							selectedExt['extension'] = ext
							selectedExt['filename'] = args.inOut[0]

				else:	# specified TEMPLATE unspecified OUTPUT
					selectedExt['extension'] = extensions[selectedExt['template']][0]
					selectedExt['filename'] = 'output.' + extensions[selectedExt['template']][0]

		else:	# unspecified TEMPLATE
			assigned = False
			defaultName = 'output.'

			if args.inOut:	# unspecified TEMPLATE and specified OUTPUT
				ext = os.path.splitext(args.inOut[0])[1][1:]

				if ext:
					for key, val in extensions.items():

						if ext in extensions[key]:
							selectedExt['template'] = key
							selectedExt['extension'] = ext
							selectedExt['filename'] = 'output.' + ext
							assigned = True
							break

					if not assigned:	# no templates match the specified extension
						defaultName = args.inOut[0][:-len(ext)]
						print('>> No template can support the specified extension')
				else:
					defaultName = args.inOut[0] + '.'
					print('>> No extension is specified')

			if not assigned:
					selectedExt['template'] = next(iter(extensions.keys()))
					selectedExt['extension'] = extensions[selectedExt['template']][0]
					selectedExt['filename'] = defaultName + selectedExt['extension']

			print('>> Default template ({}) is used'.format(selectedExt['template']))
		print('>> Output file will be saved as {}'.format(selectedExt['filename']))


		execut3(args.inExec, selectedExt)
		exit()

	else:
		parser.print_help()
	#----------PARAMETERS HANDLING ENDS HERE----------

if __name__ == '__main__':
	#----------PARSER STARTS HERE----------

	parser = MyParser(
			prog = 'VulnMin',
			usage = '%(prog)s [options]',
			formatter_class = argparse.RawTextHelpFormatter,
			description = """
			a simple vuln. report mining tool""")

	# --merge # enable vulnerabilities merging
	parser.add_argument(
		'-m', '--merge',
		dest = 'mergeON',
		action = 'store_true',
		help = 'turn on vulnerabilities merging (experimental)')

	# --file [file1 file2]	# execute w/ the supplied reports
	parser.add_argument(
		'-e', '--execute',
		dest = 'inExec',
		nargs = '*',
		metavar = 'FILE',
		help = 'takes in reports supplied by user if any, and execute the task')

	# --info [plugins, templates, scanners]	# display various status
	parser.add_argument(
		'-i', '--info',
		dest = 'inInfo',
		nargs = '+',
		choices = ['plugins', 'templates'],
		help = 'show installed plugins and templates')

	# --template [template1 template2]	# specify template(s) to use
	parser.add_argument(
		'-t', '--template',
		dest = 'inTplt',
		nargs = 1,
		metavar = 'TPLT',
		help = 'specify report template to use')

	# --output [file1 file2]	# specify output file name/type
	parser.add_argument(
		'-o', '--output',
		dest = 'inOut',
		nargs = 1,
		#type = lambda x:checkExt(x),
		metavar = 'FILENAME',
		help = 'specify the output\'s file name and type')

	'''
	# print error if no argument is supplied
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)
	'''
	args = parser.parse_args()
	#----------PARSER ENDS HERE----------

	if len(sys.argv) > 1:
		main(None, None)
	else:
		root = Tk()
		root.wm_title('vulnMin')
		app = Application(master=root)
		app.master.minsize(600,200)
		app.mainloop()
