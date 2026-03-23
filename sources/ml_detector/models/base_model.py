# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

from abc import ABC, abstractmethod

class BaseModel(ABC):
    """Base class for model training and conversion (PC side)"""

    def __init__(self, model_name):
        self.model_name = model_name
        self.input_shape = None

    @abstractmethod
    def build(self, input_shape, **kwargs):
        """Build the model architecture"""
        pass

    @abstractmethod
    def train(self, X_train, Y_train, X_val, Y_val, epochs, **kwargs):
        """Train the model"""
        pass

    @abstractmethod
    def save(self, output_path):
        """Save trained model"""
        pass

    @abstractmethod
    def convert_to_tflite(self, model_path, output_path, dataset_path):
        """Convert model to TFLite format"""
        pass

    def get_model_info(self):
        """Return model metadata"""
        return {
            "name": self.model_name,
            "input_shape": self.input_shape
        }
