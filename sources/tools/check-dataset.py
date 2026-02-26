import h5py
import numpy as np
dataset = h5py.File('dataset_train.hdf5', 'r')
X = np.array(dataset['set_x'][:])
print(f'Shape: {X.shape}')
print(f'Min: {X.min()}, Max: {X.max()}')
print(f'Mean: {X.mean()}, Std: {X.std()}')
print(f'Has NaN: {np.isnan(X).any()}')
print(f'Has Inf: {np.isinf(X).any()}')