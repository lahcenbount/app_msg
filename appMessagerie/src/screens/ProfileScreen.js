import React, { useState, useEffect } from 'react';
import { 
  View, 
  Text, 
  TextInput, 
  TouchableOpacity, 
  StyleSheet, 
  ScrollView,
  Alert,
  ActivityIndicator
} from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import { useNavigation, useRoute } from '@react-navigation/native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Ionicons } from '@expo/vector-icons';

const Tab = createBottomTabNavigator();

// Écran principal du profil
function ProfileMainScreen() {
  const navigation = useNavigation();
  const route = useRoute();
  
  const [user, setUser] = useState({
    fullName: '',
    email: '',
    profileImage: ''
  });
  
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Charger les données au démarrage du composant
  useEffect(() => {
    loadUserData();
  }, [route.params]);

  // Fonction de chargement des données utilisateur
  const loadUserData = async () => {
    setIsLoading(true);
    
    try {
      // Premièrement : vérifier les paramètres de navigation
      if (route.params) {
        const { actName, actEmail, userData } = route.params;
        
        if (actName || actEmail || userData) {
          const newUser = {
            fullName: actName || userData?.name || userData?.fullName || '',
            email: actEmail || userData?.email || '',
            profileImage: userData?.profileImage || ''
          };
          
          setUser(newUser);
          console.log('Données chargées depuis les paramètres de navigation:', newUser);
          
          // Sauvegarder les données dans AsyncStorage
          await AsyncStorage.setItem('userData', JSON.stringify(newUser));
          
          // Effacer les paramètres de navigation
          navigation.setParams({ 
            actName: undefined, 
            actEmail: undefined, 
            userData: undefined 
          });
          
          setIsLoading(false);
          return;
        }
      }

      // Deuxièmement : essayer de charger depuis AsyncStorage
      const savedUserData = await AsyncStorage.getItem('userData');
      if (savedUserData) {
        const parsedUser = JSON.parse(savedUserData);
        const userData = {
          fullName: parsedUser.fullName || parsedUser.name || '',
          email: parsedUser.email || '',
          profileImage: parsedUser.profileImage || ''
        };
        setUser(userData);
        console.log('Données chargées depuis AsyncStorage:', userData);
        setIsLoading(false);
        return;
      }

      // Troisièmement : essayer de charger depuis le serveur
      await fetchProfileFromServer();
      
    } catch (error) {
      console.error('Erreur lors du chargement des données utilisateur:', error);
      await fetchProfileFromServer();
    }
  };

  // Fonction de chargement du profil depuis le serveur
  const fetchProfileFromServer = async () => {
    try {
      const token = await AsyncStorage.getItem('userToken');
      if (!token) {
        Alert.alert('Erreur', 'Veuillez vous reconnecter');
        navigation.reset({
          index: 0,
          routes: [{ name: 'Login' }],
        });
        return;
      }

      const response = await fetch(`http://127.0.0.1:5000/profile`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        const profileData = await response.json();
        const userData = {
          fullName: profileData.fullName || profileData.name || '',
          email: profileData.email || '',
          profileImage: profileData.profileImage || ''
        };
        setUser(userData);
        
        // Sauvegarder les données mises à jour
        await AsyncStorage.setItem('userData', JSON.stringify(userData));
        console.log('Données chargées depuis le serveur:', userData);
      } else if (response.status === 401) {
        Alert.alert('Erreur', 'Session expirée, veuillez vous reconnecter');
        await AsyncStorage.multiRemove(['userToken', 'userData']);
        navigation.reset({
          index: 0,
          routes: [{ name: 'Login' }],
        });
      } else {
        Alert.alert('Erreur', 'Échec du chargement du profil');
      }
    } catch (error) {
      console.error('Erreur lors de la récupération du profil:', error);
      Alert.alert('Erreur', 'Problème de connexion au serveur');
    } finally {
      setIsLoading(false);
    }
  };

  // Fonction de changement de photo de profil
  const handleImagePicker = async () => {
    const permissionResult = await ImagePicker.requestMediaLibraryPermissionsAsync();
    
    if (!permissionResult.granted) {
      Alert.alert('Permission refusée', 'Nous avons besoin de la permission pour accéder aux photos');
      return;
    }

    const pickerResult = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: true,
      aspect: [1, 1],
      quality: 0.7,
    });

    if (!pickerResult.canceled && pickerResult.assets) {
      const selectedImage = pickerResult.assets[0];
      
      const formData = new FormData();
      formData.append('profileImage', {
        uri: selectedImage.uri,
        name: `profile-${Date.now()}.jpg`,
        type: 'image/jpeg'
      });
      formData.append('fullName', user.fullName);
      formData.append('email', user.email);

      try {
        setIsLoading(true);
        const token = await AsyncStorage.getItem('userToken');
        const response = await fetch(`http://127.0.0.1:5000/profile`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'multipart/form-data',
          },
          body: formData,
        });

        if (response.ok) {
          const updatedUser = await response.json();
          setUser(updatedUser);
          await AsyncStorage.setItem('userData', JSON.stringify(updatedUser));
          Alert.alert('Succès', 'Photo de profil mise à jour');
        } else {
          Alert.alert('Erreur', 'Échec de la mise à jour de l\'image');
        }
      } catch (error) {
        console.error(error);
        Alert.alert('Erreur', 'Problème de connexion');
      } finally {
        setIsLoading(false);
      }
    }
  };

  // Fonction de mise à jour des données du profil
  const handleUpdateProfile = async () => {
    if (!user.fullName.trim() || !user.email.trim()) {
      Alert.alert('Erreur', 'Veuillez remplir tous les champs');
      return;
    }

    try {
      setIsLoading(true);
      const token = await AsyncStorage.getItem('userToken');
      const response = await fetch(`http://127.0.0.1:5000/profile`, {
        method: 'PATCH',
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          fullName: user.fullName,
          email: user.email
        }),
      });

      if (response.ok) {
        const updatedUser = await response.json();
        setUser(updatedUser);
        await AsyncStorage.setItem('userData', JSON.stringify(updatedUser));
        setIsEditing(false);
        Alert.alert('Succès', 'Profil mis à jour');
      } else {
        const errorData = await response.json();
        Alert.alert('Erreur', errorData.message || 'Échec de la mise à jour');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Erreur', 'Problème de connexion');
    } finally {
      setIsLoading(false);
    }
  };

  // Fonction de déconnexion
  const handleLogout = () => {
    // Déconnexion immédiate sans confirmation
    AsyncStorage.multiRemove(['userToken', 'userData']);
    navigation.navigate('Login');
  };

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#4F46E5" />
        <Text style={styles.loadingText}>Chargement du profil...</Text>
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      {/* En-tête du profil */}
      <View style={styles.profileHeader}>
        <View style={styles.profileInfo}>
          <TouchableOpacity onPress={handleImagePicker}>
            <View style={styles.profileImageContainer}>
              <Text style={styles.profileNameInitials}>
                {user.fullName 
                  ? user.fullName.split(' ').map(n => n[0]).join('').toUpperCase()
                  : 'U'
                }
              </Text>
            </View>
          </TouchableOpacity>
          <View style={styles.profileDetails}>
            <Text style={styles.profileName}>
              {user.fullName || 'Nom d\'utilisateur'}
            </Text>
            <Text style={styles.profileEmail}>
              {user.email || 'exemple@email.com'}
            </Text>
          </View>
        </View>
        <TouchableOpacity onPress={handleImagePicker}>
          <Text style={styles.editPhotoText}>Changer la photo de profil</Text>
        </TouchableOpacity>
      </View>

      {/* Formulaire d'édition des données */}
      <View style={styles.sectionContainer}>
        <Text style={styles.sectionTitle}>Informations personnelles</Text>
        
        <View style={styles.formGroup}>
          <Text style={styles.label}>Nom complet</Text>
          <TextInput
            style={[styles.input, !isEditing && styles.inputDisabled]}
            value={user.fullName}
            onChangeText={text => setUser({...user, fullName: text})}
            editable={isEditing}
            placeholder="Entrez votre nom complet"
            placeholderTextColor="#999"
          />
        </View>

        <View style={styles.formGroup}>
          <Text style={styles.label}>Adresse e-mail</Text>
          <TextInput
            style={[styles.input, !isEditing && styles.inputDisabled]}
            value={user.email}
            onChangeText={text => setUser({...user, email: text})}
            keyboardType="email-address"
            editable={isEditing}
            placeholder="Entrez votre adresse e-mail"
            placeholderTextColor="#999"
          />
        </View>

        {/* Boutons de contrôle */}
        <View style={styles.buttonContainer}>
          {isEditing ? (
            <>
              <TouchableOpacity 
                style={styles.saveButton} 
                onPress={handleUpdateProfile}
                disabled={isLoading}
              >
                {isLoading ? (
                  <ActivityIndicator color="white" />
                ) : (
                  <Text style={styles.saveButtonText}>Enregistrer les modifications</Text>
                )}
              </TouchableOpacity>
              <TouchableOpacity 
                style={styles.cancelButton}
                onPress={() => setIsEditing(false)}
              >
                <Text style={styles.cancelButtonText}>Annuler</Text>
              </TouchableOpacity>
            </>
          ) : (
            <TouchableOpacity 
              style={styles.editButton}
              onPress={() => setIsEditing(true)}
            >
              <Text style={styles.editButtonText}>Modifier le profil</Text>
            </TouchableOpacity>
          )}
        </View>

        {/* Bouton de déconnexion */}
        <TouchableOpacity 
          style={styles.logoutButton}
          onPress={handleLogout}
        >
          <Text style={styles.logoutButtonText}>Se déconnecter</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

// Écran de changement de mot de passe
function ChangePasswordScreen() {
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [isLoading, setIsLoading] = useState(false);

  const handleChangePassword = async () => {
    if (!passwordData.currentPassword || !passwordData.newPassword || !passwordData.confirmPassword) {
      Alert.alert('Erreur', 'Veuillez remplir tous les champs');
      return;
    }

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      Alert.alert('Erreur', 'Les nouveaux mots de passe ne correspondent pas');
      return;
    }

    if (passwordData.newPassword.length < 6) {
      Alert.alert('Erreur', 'Le mot de passe doit contenir au moins 6 caractères');
      return;
    }

    try {
      setIsLoading(true);
      const token = await AsyncStorage.getItem('userToken');
      const response = await fetch(`http://127.0.0.1:5000/password`, {
        method: 'PATCH',
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        }),
      });

      if (response.ok) {
        Alert.alert('Succès', 'Mot de passe mis à jour');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
      } else {
        const errorData = await response.json();
        Alert.alert('Erreur', errorData.message || 'Échec de la mise à jour du mot de passe');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Erreur', 'Problème de connexion');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.sectionContainer}>
        <Text style={styles.sectionTitle}>Changer le mot de passe</Text>
        
        <View style={styles.formGroup}>
          <Text style={styles.label}>Mot de passe actuel</Text>
          <TextInput
            style={styles.input}
            secureTextEntry
            value={passwordData.currentPassword}
            onChangeText={text => setPasswordData({...passwordData, currentPassword: text})}
            placeholder="Entrez le mot de passe actuel"
            placeholderTextColor="#999"
          />
        </View>

        <View style={styles.formGroup}>
          <Text style={styles.label}>Nouveau mot de passe</Text>
          <TextInput
            style={styles.input}
            secureTextEntry
            value={passwordData.newPassword}
            onChangeText={text => setPasswordData({...passwordData, newPassword: text})}
            placeholder="Entrez le nouveau mot de passe"
            placeholderTextColor="#999"
          />
        </View>

        <View style={styles.formGroup}>
          <Text style={styles.label}>Confirmer le mot de passe</Text>
          <TextInput
            style={styles.input}
            secureTextEntry
            value={passwordData.confirmPassword}
            onChangeText={text => setPasswordData({...passwordData, confirmPassword: text})}
            placeholder="Confirmez le nouveau mot de passe"
            placeholderTextColor="#999"
          />
        </View>

        <TouchableOpacity 
          style={styles.saveButton} 
          onPress={handleChangePassword}
          disabled={isLoading}
        >
          {isLoading ? (
            <ActivityIndicator color="white" />
          ) : (
            <Text style={styles.saveButtonText}>Mettre à jour le mot de passe</Text>
          )}
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

// Écrans fictifs pour les autres onglets
function RoomsScreen() {
  return (
    <View style={styles.screenContainer}>
      <Text style={styles.screenTitle}>Salles</Text>
      <Text style={styles.screenSubtitle}>Contenu des salles à venir...</Text>
    </View>
  );
}

function StatusScreen() {
  return (
    <View style={styles.screenContainer}>
      <Text style={styles.screenTitle}>Statut</Text>
      <Text style={styles.screenSubtitle}>Contenu du statut à venir...</Text>
    </View>
  );
}

function ChatScreen() {
  return (
    <View style={styles.screenContainer}>
      <Text style={styles.screenTitle}>Discussions</Text>
      <Text style={styles.screenSubtitle}>Contenu des discussions à venir...</Text>
    </View>
  );
}

function NotificationsScreen() {
  return (
    <View style={styles.screenContainer}>
      <Text style={styles.screenTitle}>Notifications</Text>
      <Text style={styles.screenSubtitle}>Contenu des notifications à venir...</Text>
    </View>
  );
}

function SettingsScreen() {
  return (
    <View style={styles.screenContainer}>
      <Text style={styles.screenTitle}>Paramètres</Text>
      <Text style={styles.screenSubtitle}>Contenu des paramètres à venir...</Text>
    </View>
  );
}

// Composant principal avec les onglets
export default function ProfileScreen() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName;

          switch (route.name) {
            case 'Salles':
              iconName = focused ? 'home' : 'home-outline';
              break;
            case 'Statut':
              iconName = focused ? 'radio-button-on' : 'radio-button-off';
              break;
            case 'Discussions':
              iconName = focused ? 'chatbubbles' : 'chatbubbles-outline';
              break;
            case 'Notifications':
              iconName = focused ? 'notifications' : 'notifications-outline';
              break;
            case 'Profil':
              iconName = focused ? 'person' : 'person-outline';
              break;
            case 'Paramètres':
              iconName = focused ? 'settings' : 'settings-outline';
              break;
            default:
              iconName = 'help-outline';
          }

          return <Ionicons name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: '#4F46E5',
        tabBarInactiveTintColor: 'gray',
        tabBarStyle: {
          paddingBottom: 5,
          height: 60,
          backgroundColor: 'white',
        },
        headerShown: false,
      })}
    >
      <Tab.Screen name="Salles" component={RoomsScreen} />
      <Tab.Screen name="Statut" component={StatusScreen} />
      <Tab.Screen name="Discussions" component={ChatScreen} />
      <Tab.Screen name="Notifications" component={NotificationsScreen} />
      <Tab.Screen name="Profil" component={ProfileMainScreen} />
      <Tab.Screen name="Paramètres" component={SettingsScreen} />
    </Tab.Navigator>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8f9fc',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8f9fc',
  },
  loadingText: {
    marginTop: 10,
    fontSize: 16,
    color: '#666',
  },
  profileHeader: {
    alignItems: 'center',
    padding: 20,
    backgroundColor: 'white',
    borderRadius: 16,
    shadowColor: '#000',
    shadowOpacity: 0.1,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 4 },
    elevation: 5,
    margin: 20,
  },
  profileInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 15,
  },
  profileImageContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#4F46E5',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 15,
  },
  profileNameInitials: {
    color: 'white',
    fontSize: 32,
    fontWeight: 'bold',
  },
  profileDetails: {
    flex: 1,
  },
  profileName: {
    fontSize: 22,
    fontWeight: '700',
    color: '#222',
    marginBottom: 4,
  },
  profileEmail: {
    fontSize: 16,
    color: '#666',
  },
  editPhotoText: {
    color: '#4F46E5',
    fontWeight: '500',
    fontSize: 14,
  },
  sectionContainer: {
    backgroundColor: 'white',
    borderRadius: 16,
    padding: 20,
    margin: 20,
    marginTop: 0,
    shadowColor: '#000',
    shadowOpacity: 0.1,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 4 },
    elevation: 5,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#222',
    marginBottom: 20,
  },
  formGroup: {
    marginBottom: 20,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
    marginBottom: 8,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 12,
    padding: 15,
    fontSize: 16,
    backgroundColor: 'white',
  },
  inputDisabled: {
    backgroundColor: '#f5f5f5',
    color: '#666',
  },
  buttonContainer: {
    marginTop: 10,
  },
  editButton: {
    backgroundColor: '#4F46E5',
    paddingVertical: 15,
    borderRadius: 12,
    alignItems: 'center',
    marginBottom: 15,
  },
  editButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  saveButton: {
    backgroundColor: '#10B981',
    paddingVertical: 15,
    borderRadius: 12,
    alignItems: 'center',
    marginBottom: 10,
  },
  saveButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  cancelButton: {
    backgroundColor: '#6B7280',
    paddingVertical: 15,
    borderRadius: 12,
    alignItems: 'center',
    marginBottom: 15,
  },
  cancelButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  logoutButton: {
    backgroundColor: '#EF4444',
    paddingVertical: 15,
    borderRadius: 12,
    alignItems: 'center',
  },
  logoutButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  screenContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8f9fc',
  },
  screenTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 10,
  },
  screenSubtitle: {
    fontSize: 16,
    color: '#666',
  },
});