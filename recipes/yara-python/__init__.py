from pythonforandroid.recipe import CompiledComponentsPythonRecipe


class YaraPythonRecipe(CompiledComponentsPythonRecipe):
    version = '4.3.2'
    url = 'https://pypi.python.org/packages/source/y/yara-python/yara-python-{version}.tar.gz'
    depends = ['setuptools']
    call_hostpython_via_targetpython = False
    install_in_hostpython = True


recipe = YaraPythonRecipe()

