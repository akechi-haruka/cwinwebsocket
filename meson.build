project('cwinwebsocket', 'c',
        version : '1.0.0',
        default_options : ['warning_level=3', 'c_std=c2x', 'werror=true'])

add_project_arguments(
    '-DWIN32_LEAN_AND_MEAN',
    '-D_WIN32_WINNT=_WIN32_WINNT_WIN7',
    language: 'c',
)

lib_args = ['-DBUILDING_MESON_LIBRARY']

shared_library('cwinwebsocket',
        install : true,
        c_args : lib_args,
        name_prefix : '',
        sources: [
            'lib/base64.c',
            'lib/base64.h',
            'lib/http_parser.c',
            'lib/http_parser.h',
            'lib/sha1.c',
            'lib/sha1.h',
            'winwebsocket.c',
            'winwebsocket.h',
        ]
)