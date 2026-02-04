
#ifndef CE_EXPORT_H
#define CE_EXPORT_H

#ifdef CE_STATIC_DEFINE
#  define CE_EXPORT
#  define CE_NO_EXPORT
#else
#  ifndef CE_EXPORT
#    ifdef ce_EXPORTS
        /* We are building this library */
#      define CE_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define CE_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef CE_NO_EXPORT
#    define CE_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef CE_DEPRECATED
#  define CE_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef CE_DEPRECATED_EXPORT
#  define CE_DEPRECATED_EXPORT CE_EXPORT CE_DEPRECATED
#endif

#ifndef CE_DEPRECATED_NO_EXPORT
#  define CE_DEPRECATED_NO_EXPORT CE_NO_EXPORT CE_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef CE_NO_DEPRECATED
#    define CE_NO_DEPRECATED
#  endif
#endif

#endif /* CE_EXPORT_H */
