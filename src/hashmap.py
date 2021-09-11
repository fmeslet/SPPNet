#!/usr/bin/python3.5
#-*-coding:utf-8 -*-
'''
Created on 28 aout 2020

@author: Fabien Meslet-Millet
'''

import pandas as pd

import warnings
warnings.filterwarnings("ignore")

class HashMap:
    """
    Class which define an HashMap with multiple keys.
    """
    
    def __init__(self, num_keys, num_values):
        """Constructor.

        Args:
            num_keys (int): Number of keys.
            num_values (int): Number of values.
        """
        self.num_keys = num_keys
        self.num_values = num_values
        
        self.columns_keys = [str('key_{}'.format(i)) for i in range(self.num_keys)]
        self.columns_values = [str('value_{}'.format(i)) for i in range(self.num_values)]
        
        self.hashmap = pd.DataFrame(
            columns=self.columns_keys+self.columns_values+['quantity'])
        
    def add_data(self, keys, values):
        """Add data to HashMap.

        Args:
            keys (list): Keys.
            values (list): Values.
        """
        row = pd.DataFrame()

        for i in range(self.num_keys):
            row['key_{}'.format(i)] = [keys[i]]
            
        for i in range(self.num_values):
            row['value_{}'.format(i)] = [values[i]]
            
        row['quantity'] = [1]
        
        self.hashmap = pd.concat([
            self.hashmap, row]).reset_index(drop=True)
        
    def set_by_keys(self, keys, values):
        """Update values from keys.

        Args:
            keys (list): Keys.
            values (list): New values.
        """
        assert len(keys) == self.num_keys
        assert len(values) == self.num_values

        index = self.__get_index(keys=keys) 

        for i in range(self.num_values):
            self.hashmap.at[index, 'value_{}'.format(i)] = values[i]
            
        self.hashmap.at[index, 'quantity'] = self.hashmap.iloc[
            index]['quantity'] + 1
    
    def get_by_keys(self, keys):
        """Get values from keys. 

        Args:
            keys (list): Keys.

        Returns:
            list: Values associated with the keys.
        """
        assert len(keys) == self.num_keys
            
        index = self.__get_index(keys=keys)
        
        if(index is not None):
            return self.hashmap.iloc[index][
                self.columns_values + ['quantity']].values
        else:
            return None
        
    def remove_by_keys(self, keys):
        """Remove values from keys.

        Args:
            keys (list): Values associated with keys to remove.
        """
        index = self.__get_index(self, keys)
        self.hashmap = self.hashmap.drop[index]
        
    def __get_index(self, keys):
        """Get index in HashMap where values are present.

        Args:
            keys (list): Keys.

        Returns:
            int: Index where values are present.
        """
        hashmap_tmp = self.hashmap.copy()
        
        for i in range(self.num_keys):
            condition = (hashmap_tmp['key_{}'.format(i)] == keys[i])
            hashmap_tmp = hashmap_tmp[condition]
            
        try:
            return hashmap_tmp.index.values[0]
        except:
            return None
        
    def get_hashmap(self):
        """Get HashMap.

        Returns:
            pandas.DataFrame: HashMap content.
        """
        return self.hashmap