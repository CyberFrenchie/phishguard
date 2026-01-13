from setuptools import setup

setup(
    name='phishguard',
    version='0.1.0',
    py_modules=['phishguard'],          
    entry_points={
        'console_scripts': [
            'phishguard = phishguard:main',
        ]
    },
    author='Frenchie (@_CyberFrenchie)',
    author_email='acrilox@gmail.com',  
    description='Simple open-source CLI tool to detect potential phishing in URLs and text',
    long_description=open('README.md').read() if __name__ != '__main__' else '',
    long_description_content_type='text/markdown',
    url='https://github.com/CyberFrenchie/phishguard',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
