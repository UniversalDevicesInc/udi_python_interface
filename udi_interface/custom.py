import logging
#from .polylogger import LOGGER

CLOGGER = logging.getLogger(__name__)
CLOGGER.setLevel("INFO")

class Custom(dict):

    def __init__(self, poly, custom):

        self.__dict__['poly'] = poly
        self.__dict__['custom'] = custom

        CLOGGER.debug('CUSTOM: Initialzing _rawdata to empty')
        self.__dict__['_rawdata'] = {}

        """
        extradata holds extra information about the keys. The initial
        template is { key: {changed:False, new:False}}

        changed means that the key loaded from Polyglot is different
        new means that the key load from Polyglot is new
        """
        self.__dict__['_extradata'] = {}

    def dump(self):
        return self.__dict__

    def _save(self):
        key = self.__dict__['custom']
        #self.poly.custom[self.__dict__['custom']] = self._rawdata
        #self.poly._saveCustom(self.__dict__['custom'])

        CLOGGER.info('Sending data {} to Polyglot.'.format(key))
        message = {'set': [{'key': key, 'value': self.__dict__['_rawdata']}]}
        self.poly.send(message, 'custom')

    def load(self, new_data, save=False):
        """
        FIXME: this is used to update the internal data
        structure from Polyglot's database.  Should this
        be overwriting or updating the internal structure?
        """
        CLOGGER.debug('CUSTOM: load {}'.format(new_data))

        """
        typed parameter data is a bit different so we have to handle
        it differently.  It's not a key/value pair but just an array
        of dicts. 
        """
        if self.__dict__['custom'] == 'customtypedparams':
            CLOGGER.debug('CUSTOM:  -- typed parameters {}'.format(new_data))
            self.__dict__['_rawdata'] = new_data
            if save:
                self._save()
            return

        """
        typed data is a bit different so we have to handle it differently.
        It's not a key/value pair but just an array of dicts. 
        """
        if self.__dict__['custom'] == 'customtypeddata':
            CLOGGER.debug('CUSTOM:  -- typed data {}'.format(new_data))
            self.__dict__['_rawdata'] = new_data
            if save:
                self._save()
            return

        """
        we expect new_data (and _rawdata) to be key/value pairs
        in a dictionary.  Loop through new_data and create the extradata
        dictionary appropriately.
        """
        for key in new_data:
            CLOGGER.debug('CUSTOM:  -- checking {} / {}'.format(key, new_data[key]))
            edata = {'changed':False, 'new':False}

            if key in self.__dict__['_rawdata']:
                if self.__dict__['_rawdata'][key] != new_data[key]:
                    edata['changed'] = True
            else:
                edata['new'] = True

            self.__dict__['_extradata'][key] = edata

        self.__dict__['_rawdata'] = new_data

        if save:
            self._save()

    def __setattr__(self, key, notice):
        self.__dict__['_rawdata'][key] = notice
        CLOGGER.debug('CUSTOM: {} = {} ...saving'.format(key, notice))
        self._save()

    def __setitem__(self, key, notice):
        self.__dict__['_rawdata'][key] = notice
        CLOGGER.debug('CUSTOM: {} = {} ...saving'.format(key, notice))
        self._save()

    def __getattr__(self, key):
        if key in self.__dict__['_rawdata']:
            return self.__dict__['_rawdata'][key]
        else:
            return None

    def __getitem__(self, key):
        if key in self.__dict__['_rawdata']:
            return self.__dict__['_rawdata'][key]
        else:
            return None

    def __len__(self):
        return len(self.__dict__['_rawdata'])

    def delete(self, key):
        if key in self._rawdata:
            self._rawdata.pop(key)
            CLOGGER.debug('CUSTOM: delete {} ...saving'.format(key))
            self._save()

    def clear(self):
        self.__dict__['_rawdata'] = {}
        CLOGGER.debug('CUSTOM: Clear  ...saving')
        self._save()

    def __iter__(self):
        return iter(self._rawdata)

    def keys(self):
        return self._rawdata.keys()

    def items(self):
        return self._rawdata.items()

    def values(self):
        return self._rawdata.values()

    def isChanged(self, key):
        if key in self.__dict__['_extradata']:
            return self.__dict__['_extradata'][key]['changed']
        return False

    def isNew(self, key):
        if key in self.__dict__['_extradata']:
            return self.__dict__['_extradata'][key]['new']
        return False

