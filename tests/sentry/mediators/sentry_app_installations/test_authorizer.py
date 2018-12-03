from __future__ import absolute_import

import pytz

from datetime import datetime, timedelta

from sentry.coreapi import APIUnauthorized
from sentry.mediators.sentry_app_installations import Authorizer, Creator
from sentry.models import ApiToken
from sentry.testutils import TestCase


class TestAuthorizer(TestCase):
    def setUp(self):
        self.user = self.create_user()
        self.org = self.create_organization()

        self.sentry_app = self.create_sentry_app(
            name='nulldb',
            organization=self.org,
        )

        self.install, self.grant = Creator.run(
            organization=self.org,
            slug='nulldb',
            user=self.user,
        )

        self.authorizer = Authorizer(
            install=self.install,
            grant_type='authorization_code',
            code=self.grant.code,
            client_id=self.sentry_app.application.client_id,
            user=self.sentry_app.proxy_user,
        )

    def test_authorization_code_exchange(self):
        token = self.authorizer.call()
        assert token is not None

    def test_token_expires_in_eight_hours(self):
        token = self.authorizer.call()
        assert token.expires_at.hour == (datetime.now() + timedelta(hours=8)).hour

    def test_invalid_grant_type(self):
        self.authorizer.grant_type = 'stuff'

        with self.assertRaises(APIUnauthorized):
            self.authorizer.call()

    def test_missing_code(self):
        self.authorizer.code = None

        with self.assertRaises(APIUnauthorized):
            self.authorizer.call()

    def test_non_owner(self):
        self.authorizer.user = self.create_user(is_sentry_app=True)

        with self.assertRaises(APIUnauthorized):
            self.authorizer.call()

    def test_non_sentry_app(self):
        self.authorizer.user = self.create_user()

        with self.assertRaises(APIUnauthorized):
            self.authorizer.call()

    def test_missing_grant(self):
        self.authorizer.code = '123'

        with self.assertRaises(APIUnauthorized):
            self.authorizer.call()

    def test_mismatching_client_id(self):
        self.authorizer.client_id = '123'

        with self.assertRaises(APIUnauthorized):
            self.authorizer.call()

    def test_missing_code_and_refresh_token(self):
        authorizer = Authorizer(
            install=self.install,
            grant_type='authorization_code',
            client_id=self.sentry_app.application.client_id,
            user=self.sentry_app.proxy_user,
        )

        with self.assertRaises(APIUnauthorized):
            authorizer.call()

    def test_refresh_token_exchange(self):
        token = self.authorizer.call()

        self.authorizer.grant_type = 'refresh_token'
        self.authorizer.code = None
        self.authorizer.refresh_token = token.refresh_token

        new_token = self.authorizer.call()

        # Reload original token
        token = ApiToken.objects.get(id=token.id)

        # Refreshing immediately expires the active one
        assert token.expires_at < datetime.utcnow().replace(tzinfo=pytz.UTC)

        assert new_token.token != token.token
        assert new_token.refresh_token != token.refresh_token
