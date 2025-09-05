project('cwinwebsocket', 'c',
        version : '1.0.0',
        default_options : ['warning_level=3', 'c_std=c2x', 'werror=true'])

add_project_arguments(
    '-DWIN32_LEAN_AND_MEAN',
    '-D_WIN32_WINNT=_WIN32_WINNT_WIN7',
    language: 'c',
)

cc = meson.get_compiler('c')

if cc.get_id() != 'msvc'
    add_project_arguments(
        '-Wno-unused',
        language: 'c',
    )
endif

lib_args = ['-DBUILDING_MESON_LIBRARY']

inc = include_directories('.')

ws2_32_lib = cc.find_library('ws2_32')

cws_lib = static_library('cwinwebsocket',
        install : true,
        c_args : lib_args,
        name_prefix : '',
        include_directories : inc,
        dependencies: [
            ws2_32_lib
        ],
        sources: [
            'lib/base64.c',
            'lib/base64.h',
            'lib/http_parser.c',
            'lib/http_parser.h',
            'lib/sha1.c',
            'lib/sha1.h',
            'netutil.c',
            'netutil.h',
            'util.c',
            'util.h',
            'winwebsocket.c',
            'winwebsocket.h',
        ]
)

cws_dep = declare_dependency(
    link_with : cws_lib,
    include_directories : inc,
)
