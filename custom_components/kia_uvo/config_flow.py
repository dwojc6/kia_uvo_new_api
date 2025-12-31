"""Config flow for Hyundai / Kia Connect integration."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from .hyundai_kia_connect_api import Token, VehicleManager
from .hyundai_kia_connect_api.exceptions import AuthenticationError
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_PIN,
    CONF_REGION,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import (
    BRANDS,
    CONF_BRAND,
    CONF_FORCE_REFRESH_INTERVAL,
    CONF_NO_FORCE_REFRESH_HOUR_FINISH,
    CONF_NO_FORCE_REFRESH_HOUR_START,
    DEFAULT_FORCE_REFRESH_INTERVAL,
    DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
    DEFAULT_NO_FORCE_REFRESH_HOUR_START,
    DEFAULT_PIN,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    REGIONS,
    CONF_ENABLE_GEOLOCATION_ENTITY,
    CONF_USE_EMAIL_WITH_GEOCODE_API,
    DEFAULT_ENABLE_GEOLOCATION_ENTITY,
    DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
    REGION_EUROPE,
    REGION_USA,
    BRAND_HYUNDAI,
    BRAND_KIA,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PIN, default=DEFAULT_PIN): str,
        vol.Required(CONF_REGION): vol.In(REGIONS),
        vol.Required(CONF_BRAND): vol.In(BRANDS),
    }
)

STEP_REGION_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_REGION): vol.In(REGIONS),
        vol.Required(CONF_BRAND): vol.In(BRANDS),
    }
)

STEP_CREDENTIALS_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PIN, default=DEFAULT_PIN): str,
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            vol.Coerce(int), vol.Range(min=15, max=999)
        ),
        vol.Required(
            CONF_FORCE_REFRESH_INTERVAL,
            default=DEFAULT_FORCE_REFRESH_INTERVAL,
        ): vol.All(vol.Coerce(int), vol.Range(min=90, max=9999)),
        vol.Required(
            CONF_NO_FORCE_REFRESH_HOUR_START,
            default=DEFAULT_NO_FORCE_REFRESH_HOUR_START,
        ): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Required(
            CONF_NO_FORCE_REFRESH_HOUR_FINISH,
            default=DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
        ): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Optional(
            CONF_ENABLE_GEOLOCATION_ENTITY,
            default=DEFAULT_ENABLE_GEOLOCATION_ENTITY,
        ): bool,
        vol.Optional(
            CONF_USE_EMAIL_WITH_GEOCODE_API,
            default=DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
        ): bool,
    }
)


async def validate_input(hass: HomeAssistant, user_input: dict[str, Any]) -> Token:
    """Validate the user input allows us to connect."""
    try:
        api = VehicleManager.get_implementation_by_region_brand(
            user_input[CONF_REGION],
            user_input[CONF_BRAND],
            language=hass.config.language,
        )
        token: Token = await hass.async_add_executor_job(
            api.login, user_input[CONF_USERNAME], user_input[CONF_PASSWORD]
        )

        if token is None:
            raise InvalidAuth

        return token
    except AuthenticationError as err:
        raise InvalidAuth from err


def _token_to_dict(token: Token) -> dict:
    """Convert a Token object to a dictionary for storage."""
    return {
        "username": token.username,
        "password": token.password,
        "access_token": token.access_token,
        "refresh_token": token.refresh_token,
        "valid_until": token.valid_until,
        "device_id": getattr(token, "device_id", None),
    }


class HyundaiKiaConnectOptionFlowHandler(config_entries.OptionsFlow):
    """Handle an option flow for Hyundai / Kia Connect."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle options init setup."""

        if user_input is not None:
            return self.async_create_entry(
                title=self.config_entry.title, data=user_input
            )

        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                OPTIONS_SCHEMA, self.config_entry.options
            ),
        )


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Hyundai / Kia Connect."""

    VERSION = 2
    reauth_entry: ConfigEntry | None = None

    def __init__(self):
        """Initialize the config flow."""
        self._region_data = None
        self._credentials_data = None
        self._api = None
        self._otp_context = None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry):
        """Initiate options flow instance."""
        return HyundaiKiaConnectOptionFlowHandler()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step for region/brand selection."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_REGION_DATA_SCHEMA
            )

        self._region_data = user_input
        if REGIONS[self._region_data[CONF_REGION]] == REGION_EUROPE and (
            BRANDS[self._region_data[CONF_BRAND]] == BRAND_KIA
            or BRANDS[self._region_data[CONF_BRAND]] == BRAND_HYUNDAI
        ):
            return await self.async_step_credentials_token()
        return await self.async_step_credentials_password()

    async def async_step_credentials_password(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the credentials step."""
        errors = {}

        if user_input is not None:
            self._credentials_data = user_input
            full_config = {**self._region_data, **user_input}

            # Check if this is USA region which may require OTP
            region_name = REGIONS.get(self._region_data[CONF_REGION], "")
            if region_name == REGION_USA:
                try:
                    self._api = VehicleManager.get_implementation_by_region_brand(
                        self._region_data[CONF_REGION],
                        self._region_data[CONF_BRAND],
                        language=self.hass.config.language,
                    )
                    
                    # Start login process
                    token, otp_ctx = await self.hass.async_add_executor_job(
                        self._api.start_login,
                        user_input[CONF_USERNAME],
                        user_input[CONF_PASSWORD],
                        None,
                    )
                    
                    if token:
                        # No OTP required, login successful
                        # Add token data to config
                        full_config["token_data"] = _token_to_dict(token)
                        return await self._create_or_update_entry(full_config)
                    elif otp_ctx:
                        # OTP required
                        self._otp_context = otp_ctx
                        return await self.async_step_otp_destination()
                    else:
                        errors["base"] = "unknown"
                        
                except Exception as err:
                    _LOGGER.exception("Unexpected exception during login: %s", err)
                    # Check if error message indicates authentication issue
                    error_str = str(err).lower()
                    if "authentication" in error_str or "invalid" in error_str:
                        errors["base"] = "invalid_auth"
                    else:
                        errors["base"] = "unknown"
            else:
                # Non-USA regions use standard validation
                try:
                    token = await validate_input(self.hass, full_config)
                    # Add token data to config for non-USA regions too
                    full_config["token_data"] = _token_to_dict(token)
                    return await self._create_or_update_entry(full_config)
                except InvalidAuth:
                    errors["base"] = "invalid_auth"
                except Exception:
                    _LOGGER.exception("Unexpected exception")
                    errors["base"] = "unknown"

        return self.async_show_form(
            step_id="credentials_password",
            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_otp_destination(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle OTP destination selection."""
        errors = {}
        
        if user_input is not None:
            notify_type = user_input.get("notify_type")
            
            try:
                # Convert display value back to API value
                api_notify_type = "EMAIL" if notify_type.startswith("Email:") else "SMS"
                
                # Send OTP to selected destination
                await self.hass.async_add_executor_job(
                    self._api.send_otp,
                    self._otp_context["otpKey"],
                    api_notify_type,
                    self._otp_context["xid"],
                )
                
                self._otp_context["notify_type"] = api_notify_type
                self._otp_context["selected_destination"] = notify_type
                return await self.async_step_otp_code()
                
            except Exception as err:
                _LOGGER.exception("Failed to send OTP: %s", err)
                errors["base"] = "otp_send_failed"
        
        # Build schema based on available destinations
        schema_dict = {}
        choices = []
        
        if self._otp_context.get("hasEmail"):
            email = self._otp_context.get("email", "N/A")
            choices.append(f"Email: {email}")
        if self._otp_context.get("hasPhone"):
            phone = self._otp_context.get("phone", "N/A")
            choices.append(f"Phone: {phone}")
        
        if len(choices) > 1:
            schema_dict[vol.Required("notify_type")] = vol.In(choices)
            description = "Select where you would like to receive your one-time password (OTP):"
        elif len(choices) == 1:
            schema_dict[vol.Required("notify_type", default=choices[0])] = vol.In(choices)
            description = "OTP will be sent to the following destination:"
        else:
            errors["base"] = "no_otp_destination"
            description = "No OTP destination available"
        
        return self.async_show_form(
            step_id="otp_destination",
            data_schema=vol.Schema(schema_dict),
            errors=errors,
            description_placeholders={"info": description},
        )

    async def async_step_otp_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle OTP code input."""
        errors = {}
        
        if user_input is not None:
            otp_code = user_input.get("otp_code", "").strip()
            
            if not otp_code:
                errors["otp_code"] = "empty_code"
            else:
                try:
                    # Verify OTP and complete login
                    token = await self.hass.async_add_executor_job(
                        self._api.verify_otp_and_complete_login,
                        self._credentials_data[CONF_USERNAME],
                        self._credentials_data[CONF_PASSWORD],
                        self._otp_context["otpKey"],
                        self._otp_context["xid"],
                        otp_code,
                    )
                    
                    if token:
                        full_config = {**self._region_data, **self._credentials_data}
                        # IMPORTANT: Add token data to config
                        full_config["token_data"] = _token_to_dict(token)
                        return await self._create_or_update_entry(full_config)
                    else:
                        errors["base"] = "invalid_otp"
                        
                except Exception as err:
                    _LOGGER.exception("OTP verification failed: %s", err)
                    errors["base"] = "invalid_otp"
        
        # Get the friendly destination name
        destination = self._otp_context.get('selected_destination', 'your selected destination')
        method = "email" if self._otp_context.get('notify_type') == "EMAIL" else "text message"
        
        return self.async_show_form(
            step_id="otp_code",
            data_schema=vol.Schema({
                vol.Required("otp_code"): str,
            }),
            errors=errors,
            description_placeholders={
                "destination": destination,
                "method": method,
            },
        )

    async def _create_or_update_entry(self, full_config: dict[str, Any]) -> FlowResult:
        """Create new entry or update existing during reauth."""
        if self.reauth_entry is None:
            title = (
                f"{BRANDS[self._region_data[CONF_BRAND]]} "
                f"{REGIONS[self._region_data[CONF_REGION]]} "
                f"{self._credentials_data[CONF_USERNAME]}"
            )
            await self.async_set_unique_id(
                hashlib.sha256(title.encode("utf-8")).hexdigest()
            )
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title=title, data=full_config)
        else:
            self.hass.config_entries.async_update_entry(
                self.reauth_entry, data=full_config
            )
            await self.hass.config_entries.async_reload(
                self.reauth_entry.entry_id
            )
            return self.async_abort(reason="reauth_successful")

    async def async_step_credentials_token(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the credentials step."""
        errors = {}

        if user_input is not None:
            # Combine region data with credentials
            full_config = {**self._region_data, **user_input}

            try:
                token = await validate_input(self.hass, full_config)
                # Add token data to config
                full_config["token_data"] = _token_to_dict(token)
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                if self.reauth_entry is None:
                    title = f"{BRANDS[self._region_data[CONF_BRAND]]} {REGIONS[self._region_data[CONF_REGION]]} {user_input[CONF_USERNAME]}"
                    await self.async_set_unique_id(
                        hashlib.sha256(title.encode("utf-8")).hexdigest()
                    )
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title=title, data=full_config)
                else:
                    self.hass.config_entries.async_update_entry(
                        self.reauth_entry, data=full_config
                    )
                    await self.hass.config_entries.async_reload(
                        self.reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="credentials_token",
            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, user_input=None):
        """Perform reauth upon an API authentication error."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Dialog that informs the user that reauth is required."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({}),
            )
        self._reauth_config = True
        return await self.async_step_user()


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""