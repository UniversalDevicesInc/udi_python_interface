import logging

CLOGGER = logging.getLogger(__name__)
CLOGGER.setLevel("INFO")

class Custom(dict):

    def __init__(self, poly, custom):

        self.__dict__['poly'] = poly
        self.__dict__['custom'] = custom

        CLOGGER.debug('CUSTOM: Initializing _rawdata to empty')
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

    # This loads new_data (it overwrites the previous content with new_data)
    def load(self, new_data, save=False):

        if new_data is None:
            self.__dict__['_rawdata'] = {}
            return

        """
        FIXME: this is used to update the internal data
        structure from Polyglot's database. This overwrites the internal structure
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


    # Same as load, but updates with new_data (does not overwrite)
    def update(self, update, save=False):
        if update is None:
            return

        new_data = self.__dict__['_rawdata']
        has_changes = self._deep_update(new_data, update)

        if has_changes:
            self.load(new_data, True)

    def _deep_update(self, original, update):
        has_changes = False
        # Recursively update a dictionary with another dictionary.
        for key, value in update.items():
            # If assigning an object, go one level deeper
            if isinstance(value, dict):
                # The original object must either have a key assigned to an object, or not yet exist
                if key not in original or not isinstance(original[key], dict):
                    original[key] = {}

                has_changes = has_changes or self._deep_update(original[key], value)
            else:
                if original.get(key) != value:
                    has_changes = True
                    original[key] = value

        return has_changes

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

    def __contains__(self, item):
        return item in self.__dict__['_rawdata']

    def __repr__(self):
        return repr(self.__dict__['_rawdata'])

    def __str__(self):
        return str(self.__dict__['_rawdata'])

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

    def get(self, key, default=None):
        if key in self._rawdata:
            return self.__getitem__(key)
        else:
            return default

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

