"""Curated synthetic release checks; excludes the private public-probe harness."""
import unittest

import test_portable_source
import test_portable_command_handoff
import test_portable_operations

SOURCE_CASES = (
    'test_config_is_user_selected_private_and_rejects_unsafe_modes',
    'test_config_rejects_checkout_paths_unsafe_secret_and_event_scope',
    'test_signed_event_preserves_complete_source_without_http_listener',
    'test_interrupted_stage_holds_attention_across_restart_without_refetch',
    'test_wrong_owner_note_and_provider_limits_never_preserve',
    'test_shared_note_not_owned_by_configured_user_never_reaches_owner_command',
    'test_retryable_source_failures_remain_pending_and_permanent_failures_hold',
    'test_worker_boundary_sends_exact_note_and_restores_source_bytes',
)


def suite():
    result = unittest.TestSuite()
    for name in SOURCE_CASES:
        result.addTest(test_portable_source.PortableSourceTests(name))
    result.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_portable_command_handoff))
    result.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_portable_operations))
    return result


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(not result.wasSuccessful())
