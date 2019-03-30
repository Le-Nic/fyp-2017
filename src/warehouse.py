import pandas as pd
import numpy as np


vulnList = []

class vulnStore():

	def __init__(self, scanner, ip, host, os, columns):
		self.scanner = scanner

		self.ip = ip
		self.host = host # hostname
		self.os = os

		self.data = pd.DataFrame(columns=columns)
		vulnList.append(self)

	def add(self, data):
		self.data = self.data.append([data], ignore_index=True)
