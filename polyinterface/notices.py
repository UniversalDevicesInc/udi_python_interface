class Notices(dict):
    __exists = False

    def __init__(self, poly):
        if self.__exists:
            warnings.warn('Only one Notices is allowed.')
            return

        Notices.__exists = True

        self.__dict__['poly'] = poly

        """ TODO:
            What's the best way to initialize the dict?  We don't
            get the info from polyglot until after we send a request
            to get all config info.  At that point, this class will
            have been instansiated.  So we probably need to start
            with an empty dictionary.
        """
        self.__dict__['_notices'] = {}
        #self._loaded = False

    def dump(self):
        return self.__dict__

    def _save(self):
        self.poly.custom['notices'] = self._notices
        self.poly.saveCustom('notices')

    def __setattr__(self, key, notice):
        self.__dict__['_notices'][key] = notice
        self._save()

    def __setitem__(self, key, notice):
        self.__dict__['_notices'][key] = notice
        self._save()

    def __getattr__(self, key):
        if key in self.__dict__['_notices']:
            return self.__dict__['_notices'][key]
        else:
            return None

    def __getitem__(self, key):
        if key in self.__dict__['_notices']:
            return self.__dict__['_notices'][key]
        else:
            return None

    def load(self, notices):
        self._loaded = True
        self.__dict__['_notices'] = notices

    def delete(self, key):
        if key in self._notices:
            self._notices.pop(key)
            self._save()

    def clear(self):
        self._notices = {}
        self._save()

    def __iter__(self):
        return iter(self._notices)

    def keys(self):
        return self._notices.keys()

    def items(self):
        return self._notices.items()

    def values(self):
        return self._notices.values()

